// Shared helper for custom (non-Cognito) email verification codes.
//
// Used by api/forgot-password.js (password reset) and api/signup-verify.js
// (signup email verification, and forced/migrated-user password resets).
// Generates a 6-digit code, stores a HASH of it in DynamoDB with a short
// TTL, and sends the plaintext code to the user via Brevo SMTP. Cognito is
// never asked to send an email in this flow — it is only used afterwards
// (AdminSetUserPassword / AdminUpdateUserAttributes) to apply the result
// once we've verified the code ourselves.
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { DynamoDBClient, GetItemCommand, PutItemCommand, DeleteItemCommand, UpdateItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';

// ── Brevo SMTP configuration ────────────────────────────────────────────
// Required env vars (see README / deployment docs):
//   BREVO_SMTP_HOST  e.g. smtp-relay.brevo.com
//   BREVO_SMTP_PORT  e.g. 587
//   BREVO_SMTP_USER  Brevo SMTP login (usually your Brevo account email)
//   BREVO_SMTP_PASS  Brevo SMTP key (NOT your Brevo account password)
//   EMAIL_FROM       verified sender address, e.g. noreply@rentnivas.com
//   EMAIL_FROM_NAME  display name, e.g. "Rent Nivas"
const BREVO_SMTP_HOST = process.env.BREVO_SMTP_HOST;
const BREVO_SMTP_PORT = Number(process.env.BREVO_SMTP_PORT || 587);
const BREVO_SMTP_USER = process.env.BREVO_SMTP_USER;
const BREVO_SMTP_PASS = process.env.BREVO_SMTP_PASS;
const EMAIL_FROM = process.env.EMAIL_FROM || 'rentnivas@gmail.com';
const EMAIL_FROM_NAME = process.env.EMAIL_FROM_NAME || 'Rent Nivas';

const CODES_TABLE = process.env.TABLE_VERIFICATION_CODES || 'VerificationCodes';
const CODE_TTL_MINUTES = 15;
const MAX_ATTEMPTS = 5;

const ddb = new DynamoDBClient({ region: REGION });

// Lazily-created singleton SMTP transporter (re-used across invocations on
// warm Lambda/Vercel function instances).
let transporter = null;
function getTransporter() {
  if (transporter) return transporter;
  if (!BREVO_SMTP_HOST || !BREVO_SMTP_USER || !BREVO_SMTP_PASS) {
    const missing = [
      !BREVO_SMTP_HOST && 'BREVO_SMTP_HOST',
      !BREVO_SMTP_USER && 'BREVO_SMTP_USER',
      !BREVO_SMTP_PASS && 'BREVO_SMTP_PASS'
    ].filter(Boolean).join(', ');
    throw new Error(`Brevo SMTP is not configured — missing env var(s): ${missing}`);
  }
  console.log(`[Brevo][getTransporter] creating SMTP transporter host=${BREVO_SMTP_HOST} port=${BREVO_SMTP_PORT} user=${BREVO_SMTP_USER}`);
  transporter = nodemailer.createTransport({
    host: BREVO_SMTP_HOST,
    port: BREVO_SMTP_PORT,
    // Brevo uses STARTTLS on 587 (secure:false + upgrade) and implicit TLS on 465.
    secure: BREVO_SMTP_PORT === 465,
    auth: { user: BREVO_SMTP_USER, pass: BREVO_SMTP_PASS }
  });
  return transporter;
}

function generateCode() {
  // 6-digit numeric code, zero-padded, cryptographically random.
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  console.log(`[Brevo][generateCode] generated a 6-digit code (value not logged)`);
  return code;
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
    email: String(email).toLowerCase(),
    type: purpose,
    codeHash: hashCode(code, email),
    attempts: 0,
    used: false,
    createdAt: now,
    expiresAt,
    // DynamoDB native TTL attribute (seconds since epoch). Requires TTL to be
    // enabled on this table with attribute name "ttl" — see README note.
    ttl: Math.floor(expiresAt / 1000)
  };
  console.log(`[DynamoDB][storeCode] purpose=${purpose} email=${email} table=${CODES_TABLE} expiresAt=${new Date(expiresAt).toISOString()}`);
  try {
    await ddb.send(new PutItemCommand({ TableName: CODES_TABLE, Item: marshall(item) }));
    console.log(`[DynamoDB][storeCode] stored OK pk=${item.pk}`);
  } catch (err) {
    console.error(`[DynamoDB][storeCode] PutItem FAILED for pk=${item.pk} table=${CODES_TABLE}:`, err);
    throw new Error(`Could not store verification code (DynamoDB PutItem on "${CODES_TABLE}" failed): ${err.message || err}`);
  }
  return item;
}

async function getCode(purpose, email) {
  const pk = codeKey(purpose, email);
  try {
    const resp = await ddb.send(new GetItemCommand({ TableName: CODES_TABLE, Key: marshall({ pk }) }));
    if (!resp.Item) {
      console.warn(`[DynamoDB][getCode] no record found for pk=${pk} table=${CODES_TABLE}`);
      return null;
    }
    const record = unmarshall(resp.Item);
    if (record.used) {
      console.warn(`[DynamoDB][getCode] code already used for pk=${pk} — rejecting reuse`);
      return null;
    }
    return record;
  } catch (err) {
    console.error(`[DynamoDB][getCode] GetItem FAILED for pk=${pk} table=${CODES_TABLE}:`, err);
    throw new Error(`Could not look up verification code (DynamoDB GetItem on "${CODES_TABLE}" failed): ${err.message || err}`);
  }
}

async function markCodeUsed(purpose, email) {
  const pk = codeKey(purpose, email);
  try {
    await ddb.send(new UpdateItemCommand({
      TableName: CODES_TABLE,
      Key: marshall({ pk }),
      UpdateExpression: 'SET used = :true',
      ExpressionAttributeValues: marshall({ ':true': true })
    }));
    console.log(`[DynamoDB][markCodeUsed] marked used pk=${pk}`);
  } catch (err) {
    console.error(`[DynamoDB][markCodeUsed] UpdateItem FAILED for pk=${pk} table=${CODES_TABLE} (non-fatal):`, err);
  }
}

async function deleteCode(purpose, email) {
  const pk = codeKey(purpose, email);
  try {
    await ddb.send(new DeleteItemCommand({ TableName: CODES_TABLE, Key: marshall({ pk }) }));
    console.log(`[DynamoDB][deleteCode] removed pk=${pk}`);
  } catch (err) {
    // Cleanup failure shouldn't block the caller — just log it loudly.
    console.error(`[DynamoDB][deleteCode] DeleteItem FAILED for pk=${pk} table=${CODES_TABLE} (non-fatal):`, err);
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
    console.error(`[DynamoDB][bumpAttempts] UpdateItem FAILED for pk=${pk} table=${CODES_TABLE} (non-fatal):`, err);
  }
}

// purpose -> { subject, build(code) -> { text, html } }
// 'signup_verify'    -> "Verify Your Rent Nivas Account"
// 'password_reset'   -> "Rent Nivas Password Reset Code"
// 'forced_reset'     -> "Action Required - Reset Your Rent Nivas Password"
function buildEmail(purpose, code) {
  if (purpose === 'signup_verify') {
    return {
      subject: 'Verify Your Rent Nivas Account',
      text: `Welcome to Rent Nivas!\n\nYour email verification code is: ${code}\n\nThis code expires in ${CODE_TTL_MINUTES} minutes.\n\nIf you didn't create a Rent Nivas account, you can ignore this email.`,
      html: `<p>Welcome to Rent Nivas!</p><p>Your email verification code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p><p>This code expires in ${CODE_TTL_MINUTES} minutes.</p><p>If you didn't create a Rent Nivas account, you can ignore this email.</p>`
    };
  }
  if (purpose === 'forced_reset') {
    return {
      subject: 'Action Required - Reset Your Rent Nivas Password',
      text: `Your Rent Nivas account requires a password reset before you can sign in again.\n\nYour reset code is: ${code}\n\nThis code expires in ${CODE_TTL_MINUTES} minutes. Enter it on the password reset page to choose a new password.`,
      html: `<p>Your Rent Nivas account requires a password reset before you can sign in again.</p><p>Your reset code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p><p>This code expires in ${CODE_TTL_MINUTES} minutes. Enter it on the password reset page to choose a new password.</p>`
    };
  }
  // default: password_reset
  return {
    subject: 'Rent Nivas Password Reset Code',
    text: `We received a request to reset your Rent Nivas password.\n\nYour reset code is: ${code}\n\nThis code expires in ${CODE_TTL_MINUTES} minutes. If you didn't request this, you can ignore this email.`,
    html: `<p>We received a request to reset your Rent Nivas password.</p><p>Your reset code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px;">${code}</p><p>This code expires in ${CODE_TTL_MINUTES} minutes. If you didn't request this, you can ignore this email.</p>`
  };
}

// This is the exact function the Brevo email send happens in. Every failure
// path is logged with full context and RE-THROWN — nothing is swallowed —
// so the caller (api/forgot-password.js / api/signup-verify.js) sees it and
// returns a real error to the frontend instead of silently pretending the
// email went out.
async function sendCodeEmail(purpose, toEmail, code) {
  const { subject, text, html } = buildEmail(purpose, code);
  console.log(`[Brevo][sendCodeEmail] >>> preparing email | to=${toEmail} from=${EMAIL_FROM} purpose=${purpose}`);
  try {
    const tx = getTransporter();
    const result = await tx.sendMail({
      from: `"${EMAIL_FROM_NAME}" <${EMAIL_FROM}>`,
      to: toEmail,
      subject,
      text,
      html
    });
    console.log(`[Brevo][sendCodeEmail] <<< Brevo ACCEPTED the email. messageId=${result.messageId} to=${toEmail}`);
    return result;
  } catch (err) {
    // ── EXACT FAILURE POINT ──────────────────────────────────────────────
    // Common causes surfaced here:
    //  - Authentication failed → BREVO_SMTP_USER / BREVO_SMTP_PASS wrong, or
    //    using the Brevo account password instead of an SMTP key.
    //  - Sender not verified → EMAIL_FROM isn't a verified sender/domain in
    //    the Brevo dashboard (Senders & IP > Senders).
    //  - Connection timeout / ECONNREFUSED → BREVO_SMTP_HOST/PORT wrong, or
    //    outbound SMTP (port 587/465) blocked by the hosting environment.
    console.error('[Brevo][sendCodeEmail] !!! Brevo SMTP send FAILED !!!', {
      to: toEmail,
      from: EMAIL_FROM,
      host: BREVO_SMTP_HOST,
      port: BREVO_SMTP_PORT,
      errorName: err.name,
      errorMessage: err.message,
      smtpCode: err.responseCode || err.code
    });
    const wrapped = new Error(`Brevo send failed (${err.name || 'Error'}): ${err.message || 'Unknown Brevo SMTP error'}`);
    wrapped.cause = err;
    throw wrapped; // never swallow — caller must see this and the request must fail loudly.
  }
}

module.exports = {
  REGION, EMAIL_FROM, EMAIL_FROM_NAME, CODES_TABLE, CODE_TTL_MINUTES, MAX_ATTEMPTS,
  generateCode, hashCode, storeCode, getCode, markCodeUsed, deleteCode, bumpAttempts, sendCodeEmail
};
