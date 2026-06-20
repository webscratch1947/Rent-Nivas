// Custom (non-Cognito) password reset flow.
//
//   POST /api/forgot-password { action: 'request', email }
//     -> generates a 6-digit code, stores a hash of it in DynamoDB, sends it
//        via SES. Cognito is NOT touched in this step.
//
//   POST /api/forgot-password { action: 'confirm', email, code, newPassword }
//     -> verifies the code against DynamoDB, then calls Cognito
//        AdminSetUserPassword (Permanent: true) to actually change the
//        password and clear any FORCE_CHANGE_PASSWORD / RESET_REQUIRED status.
const { CognitoIdentityProviderClient, AdminGetUserCommand, AdminSetUserPasswordCommand } = require('@aws-sdk/client-cognito-identity-provider');
const { REGION, USER_POOL_ID, send, parseBody } = require('./_auth');
const { generateCode, storeCode, getCode, deleteCode, bumpAttempts, sendCodeEmail, hashCode, MAX_ATTEMPTS } = require('./_ses');

const cognito = new CognitoIdentityProviderClient({ region: REGION });

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST') return send(res, 405, { error: { message: 'Method not allowed' } });

  let body;
  try {
    body = await parseBody(req);
  } catch (err) {
    return send(res, 400, { error: { message: 'Invalid request body' } });
  }

  const action = body.action;
  const email = String(body.email || '').trim().toLowerCase();
  if (!email) return send(res, 400, { error: { message: 'Email is required' } });

  if (action === 'request') {
    console.log(`[ForgotPassword] ── request received for email=${email}`);
    try {
      // Confirm the account actually exists before generating/sending anything.
      try {
        await cognito.send(new AdminGetUserCommand({ UserPoolId: USER_POOL_ID, Username: email }));
      } catch (lookupErr) {
        console.warn(`[ForgotPassword] AdminGetUser lookup failed for ${email} (treating as "user not found"):`, lookupErr.message || lookupErr);
        // Don't reveal account existence to the caller — but DO return 200
        // so the frontend shows the generic "check your email" state.
        return send(res, 200, { data: {} });
      }

      const code = generateCode();
      console.log(`[ForgotPassword] generated a reset code for ${email} (code itself is not logged)`);

      await storeCode('password_reset', email, code);

      console.log(`[ForgotPassword] about to call sendCodeEmail() for ${email}`);
      await sendCodeEmail('password_reset', email, code);
      console.log(`[ForgotPassword] ✅ SES send completed successfully for ${email}`);

      return send(res, 200, { data: {} });
    } catch (err) {
      // If we got here, either DynamoDB storeCode() or SES sendCodeEmail()
      // threw — both log their own detailed context already. This is the
      // top-level point where that failure becomes a real HTTP error
      // instead of a silently "successful" response.
      console.error(`[ForgotPassword] ❌ request FAILED for ${email}:`, err);
      return send(res, 500, { error: { message: err.message || 'Could not send reset code' } });
    }
  }

  if (action === 'confirm') {
    const code = String(body.code || '').trim();
    const newPassword = body.newPassword;
    if (!code) return send(res, 400, { error: { message: 'Reset code is required' } });
    if (!newPassword) return send(res, 400, { error: { message: 'New password is required' } });

    console.log(`[ForgotPassword] ── confirm received for email=${email}`);
    try {
      const record = await getCode('password_reset', email);
      if (!record) {
        console.warn(`[ForgotPassword] confirm: no code record found for ${email}`);
        return send(res, 400, { error: { message: 'Invalid or expired code. Please request a new one.' } });
      }
      if (Date.now() > record.expiresAt) {
        console.warn(`[ForgotPassword] confirm: code expired for ${email}`);
        await deleteCode('password_reset', email);
        return send(res, 400, { error: { message: 'This code has expired. Please request a new one.' } });
      }
      if ((record.attempts || 0) >= MAX_ATTEMPTS) {
        console.warn(`[ForgotPassword] confirm: too many attempts for ${email}`);
        await deleteCode('password_reset', email);
        return send(res, 400, { error: { message: 'Too many incorrect attempts. Please request a new code.' } });
      }
      if (record.codeHash !== hashCode(code, email)) {
        await bumpAttempts('password_reset', email);
        console.warn(`[ForgotPassword] confirm: code mismatch for ${email}`);
        return send(res, 400, { error: { message: 'Incorrect code. Please try again.' } });
      }

      await cognito.send(new AdminSetUserPasswordCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        Password: newPassword,
        Permanent: true
      }));
      console.log(`[ForgotPassword] ✅ Cognito password updated (Permanent) for ${email}`);

      await deleteCode('password_reset', email);
      return send(res, 200, { data: {} });
    } catch (err) {
      console.error(`[ForgotPassword] ❌ confirm FAILED for ${email}:`, err);
      return send(res, 500, { error: { message: err.message || 'Could not reset password' } });
    }
  }

  return send(res, 400, { error: { message: 'Unsupported action' } });
};
