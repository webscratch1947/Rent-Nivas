// Shared helper for custom (non-Cognito) email verification codes.
//
// Used by api/forgot-password.js (password reset) and api/signup-verify.js
// (signup email verification). Generates a 6-digit code, stores a HASH of it
// in DynamoDB with a short TTL, and sends the plaintext code to the user via
// AWS SES. Cognito is never asked to send an email in this flow — it is only
// used afterwards (AdminSetUserPassword / AdminUpdateUserAttributes) to apply
// the result once we've verified the code ourselves.
const crypto = require('crypto');
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
const { DynamoDBClient, GetItemCommand, PutItemCommand, DeleteItemCommand, UpdateItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
// SES isn't necessarily verified in the same region as the rest of the app —
// override with SES_REGION if the verified identity lives elsewhere.
const SES_REGION = process.env.SES_REGION || REGION;
// Sender address. Must be a VERIFIED identity in SES (Console > Verified
// identities) for the SES_REGION above, or every send will fail with
// MessageRejected: "Email address is not verified."
const SES_FROM_EMAIL = process.env.SES_FROM_EMAIL;
const CODES_TABLE = process.env.TABLE_VERIFICATION_CODES || 'VerificationCodes';
const CODE_TTL_MINUTES = 15;
const MAX_ATTEMPTS = 5;

const ses = new SESClient({ region: SES_REGION });
const ddb = new DynamoDBClient({ region: REGION });

function generateCode() {
  // 6-digit numeric code, zero-padded, cryptographically random.
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}

function hashCode(code, email) {
  return crypto.createHash('sha256').update(`${code}:${String(email).toLowerCase()}`).digest('hex');
}

function codeKey(purpose, email) {
  return `${purpose}#${String(email).toLowerCase()}`;
}

async function storeCode(purpose, email, code) {
  const now = Date.now();
  const expiresAt = now + CODE_TTL_MINUTES * 60 * 1000;
  const item = {
    pk: codeKey(purpose, email),
    codeHash: hashCode(code, email),
    attempts: 0,
    createdAt: now,
    expiresAt,
    // DynamoDB native TTL attribute (seconds since epoch). Requires TTL to be
    // enabled on this table with attribute name "ttl" — see README note.
    ttl: Math.floor(expiresAt / 1000)
  };
  console.log(`[SES][storeCode] purpose=${purpose} email=${email} table=${CODES_TABLE} expiresAt=${new Date(expiresAt).toISOString()}`);
  try {
    await ddb.send(new PutItemCommand({ TableName: CODES_TABLE, Item: marshall(item) }));
    console.log(`[SES][storeCode] stored OK pk=${item.pk}`);
  } catch (err) {
    console.error(`[SES][storeCode] DynamoDB PutItem FAILED for pk=${item.pk} table=${CODES_TABLE}:`, err);
    throw new Error(`Could not store verification code (DynamoDB PutItem on "${CODES_TABLE}" failed): ${err.message || err}`);
  }
  return item;
}

async function getCode(purpose, email) {
  const pk = codeKey(purpose, email);
  try {
    const resp = await ddb.send(new GetItemCommand({ TableName: CODES_TABLE, Key: marshall({ pk }) }));
    if (!resp.Item) {
      console.warn(`[SES][getCode] no record found for pk=${pk} table=${CODES_TABLE}`);
      return null;
    }
    return unmarshall(resp.Item);
  } catch (err) {
    console.error(`[SES][getCode] DynamoDB GetItem FAILED for pk=${pk} table=${CODES_TABLE}:`, err);
    throw new Error(`Could not look up verification code (DynamoDB GetItem on "${CODES_TABLE}" failed): ${err.message || err}`);
  }
}

async function deleteCode(purpose, email) {
  const pk = codeKey(purpose, email);
  try {
    await ddb.send(new DeleteItemCommand({ TableName: CODES_TABLE, Key: marshall({ pk }) }));
    console.log(`[SES][deleteCode] removed pk=${pk}`);
  } catch (err) {
    // Cleanup failure shouldn't block the caller — just log it loudly.
    console.error(`[SES][deleteCode] DynamoDB DeleteItem FAILED for pk=${pk} table=${CODES_TABLE} (non-fatal):`, err);
  }
}

async function bumpAttempts(purpose, email) {
  const pk = codeKey(purpose, email);
  try {
    await ddb.send(new UpdateItemCommand({
      TableName: CODES_TABLE,
      Key: marshall({ pk }),
      UpdateExpression: 'SET attempts = if_not_exists(attempts, :zero) + :one',
      ExpressionAttributeValues: marshall({ ':zero': 0, ':one': 1 })
    }));
  } catch (err) {
    console.error(`[SES][bumpAttempts] DynamoDB UpdateItem FAILED for pk=${pk} table=${CODES_TABLE} (non-fatal):`, err);
  }
}

function buildEmail(purpose, code) {
  if (purpose === 'signup_verify') {
    return {
      subject: 'Verify your email — Rent Nivas',
      text: `Welcome to Rent Nivas!\n\nYour email verification code is: ${code}\n\nThis code expires in ${CODE_TTL_MINUTES} minutes.\n\nIf you didn't create a Rent Nivas account, you can ignore this email.`,
      html: `<p>Welcome to Rent Nivas!</p><p>Your email verification code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p><p>This code expires in ${CODE_TTL_MINUTES} minutes.</p><p>If you didn't create a Rent Nivas account, you can ignore this email.</p>`
    };
  }
  return {
    subject: 'Your password reset code — Rent Nivas',
    text: `We received a request to reset your Rent Nivas password.\n\nYour reset code is: ${code}\n\nThis code expires in ${CODE_TTL_MINUTES} minutes. If you didn't request this, you can ignore this email.`,
    html: `<p>We received a request to reset your Rent Nivas password.</p><p>Your reset code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p><p>This code expires in ${CODE_TTL_MINUTES} minutes. If you didn't request this, you can ignore this email.</p>`
  };
}

// This is the exact function the SES email send happens in. Every failure
// path is logged with full context and RE-THROWN — nothing is swallowed —
// so the caller (api/forgot-password.js / api/signup-verify.js) sees it and
// returns a real error to the frontend instead of silently pretending the
// email went out.
async function sendCodeEmail(purpose, toEmail, code) {
  const { subject, text, html } = buildEmail(purpose, code);
  console.log(`[SES][sendCodeEmail] >>> preparing SendEmailCommand | to=${toEmail} from=${SES_FROM_EMAIL} region=${SES_REGION} purpose=${purpose}`);
  const params = {
    Destination: { ToAddresses: [toEmail] },
    Message: {
      Subject: { Data: subject, Charset: 'UTF-8' },
      Body: {
        Text: { Data: text, Charset: 'UTF-8' },
        Html: { Data: html, Charset: 'UTF-8' }
      }
    },
    Source: SES_FROM_EMAIL
  };
  try {
    const result = await ses.send(new SendEmailCommand(params));
    console.log(`[SES][sendCodeEmail] <<< SES ACCEPTED the email. MessageId=${result.MessageId} to=${toEmail}`);
    return result;
  } catch (err) {
    // ── EXACT FAILURE POINT ──────────────────────────────────────────────
    // Common causes surfaced here:
    //  - MessageRejected "Email address is not verified" → SES_FROM_EMAIL
    //    (or, in sandbox mode, the destination address) isn't a verified
    //    identity in SES_REGION.
    //  - AccessDenied / not authorized to perform ses:SendEmail → the
    //    Vercel function's AWS credentials don't have an SES permission.
    //  - Sandbox mode → any destination that isn't itself verified is
    //    rejected outright, even if the FROM address is verified.
    console.error('[SES][sendCodeEmail] !!! SES SendEmailCommand FAILED !!!', {
      to: toEmail,
      from: SES_FROM_EMAIL,
      region: SES_REGION,
      errorName: err.name,
      errorMessage: err.message,
      awsErrorCode: err.Code || err.code,
      httpStatusCode: err.$metadata && err.$metadata.httpStatusCode,
      requestId: err.$metadata && err.$metadata.requestId
    });
    const wrapped = new Error(`SES send failed (${err.name || 'Error'}): ${err.message || 'Unknown SES error'}`);
    wrapped.cause = err;
    throw wrapped; // never swallow — caller must see this and the request must fail loudly.
  }
}

module.exports = {
  REGION, SES_REGION, SES_FROM_EMAIL, CODES_TABLE, CODE_TTL_MINUTES, MAX_ATTEMPTS,
  generateCode, hashCode, storeCode, getCode, deleteCode, bumpAttempts, sendCodeEmail
};
