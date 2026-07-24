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
const EMAIL_FROM = process.env.EMAIL_FROM;
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
  if (!BREVO_SMTP_HOST || !BREVO_SMTP_USER || !BREVO_SMTP_PASS || !EMAIL_FROM) {
    const missing = [
      !BREVO_SMTP_HOST && 'BREVO_SMTP_HOST',
      !BREVO_SMTP_USER && 'BREVO_SMTP_USER',
      !BREVO_SMTP_PASS && 'BREVO_SMTP_PASS',
      !EMAIL_FROM && 'EMAIL_FROM'
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

// purpose -> { subject, text, html }
// 'signup_verify'  -> account registration verification code
// 'password_reset' -> voluntary password reset
// 'forced_reset'   -> migrated/admin-required password reset
function _emailWrap(body) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f5f0eb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:32px 16px;">
    <tr><td align="center">
      <table width="100%" style="max-width:480px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 2px 16px rgba(0,0,0,.08);">
        <tr><td style="background:#c07a5a;padding:24px 32px;">
          <div style="font-size:22px;font-weight:800;color:#fff;letter-spacing:-.3px;">🏠 Rent Nivas</div>
        </td></tr>
        <tr><td style="padding:32px;">
          ${body}
          <hr style="border:none;border-top:1px solid #f0ebe6;margin:24px 0;">
          <p style="font-size:12px;color:#999;margin:0;">This email was sent by Rent Nivas. If you have questions, reply to this email or contact us at ${EMAIL_FROM}</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

function _codeBlock(code) {
  return `<div style="background:#f5f0eb;border-radius:12px;padding:20px;text-align:center;margin:20px 0;">
    <div style="font-size:13px;color:#999;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px;">Your verification code</div>
    <div style="font-size:36px;font-weight:900;letter-spacing:8px;color:#c07a5a;font-family:monospace;">${code}</div>
    <div style="font-size:12px;color:#bbb;margin-top:8px;">Expires in ${CODE_TTL_MINUTES} minutes</div>
  </div>`;
}

function buildEmail(purpose, code) {
  if (purpose === 'signup_verify') {
    const body = `
      <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;color:#1a1a1a;">Verify your account</h2>
      <p style="color:#666;font-size:15px;margin:0 0 4px;">Welcome to Rent Nivas! Use the code below to verify your email address and activate your account.</p>
      ${_codeBlock(code)}
      <p style="color:#999;font-size:13px;margin:0;">If you didn't sign up for Rent Nivas, you can safely ignore this email.</p>`;
    return {
      subject: 'Your Rent Nivas account verification code',
      text: `Welcome to Rent Nivas!

Your account verification code is: ${code}

This code expires in ${CODE_TTL_MINUTES} minutes.

If you didn't sign up for Rent Nivas, you can safely ignore this email.`,
      html: _emailWrap(body)
    };
  }
  if (purpose === 'forced_reset') {
    const body = `
      <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;color:#1a1a1a;">Password reset required</h2>
      <p style="color:#666;font-size:15px;margin:0 0 4px;">Your Rent Nivas account requires a password reset before you can sign in. Use the code below to set a new password.</p>
      ${_codeBlock(code)}
      <p style="color:#999;font-size:13px;margin:0;">If you didn't request this, contact us at ${EMAIL_FROM} immediately.</p>`;
    return {
      subject: 'Action required — Reset your Rent Nivas password',
      text: `Your Rent Nivas account requires a password reset.

Your reset code is: ${code}

This code expires in ${CODE_TTL_MINUTES} minutes. Enter it on the password reset page to set a new password.

If you didn't request this, contact ${EMAIL_FROM} immediately.`,
      html: _emailWrap(body)
    };
  }
  // default: password_reset (voluntary)
  const body = `
    <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;color:#1a1a1a;">Reset your password</h2>
    <p style="color:#666;font-size:15px;margin:0 0 4px;">We received a request to reset the password for your Rent Nivas account. Use the code below to set a new password.</p>
    ${_codeBlock(code)}
    <p style="color:#999;font-size:13px;margin:0;">If you didn't request a password reset, you can safely ignore this email — your password has not been changed.</p>`;
  return {
    subject: 'Your Rent Nivas password reset code',
    text: `We received a request to reset your Rent Nivas password.

Your reset code is: ${code}

This code expires in ${CODE_TTL_MINUTES} minutes. If you didn't request this, you can safely ignore this email.`,
    html: _emailWrap(body)
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
