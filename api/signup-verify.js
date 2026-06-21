// Custom (non-Cognito) signup email verification flow.
//
//   POST /api/signup-verify { action: 'request', email, password, name, referral_code }
//     -> Creates the Cognito user server-side with MessageAction:'SUPPRESS'
//        (so Cognito never sends its own welcome/confirmation email),
//        immediately sets the user's real chosen password as permanent
//        (so they are never stuck in FORCE_CHANGE_PASSWORD), marks
//        email_verified=false, then generates+stores+sends our own code
//        via Brevo.
//
//   POST /api/signup-verify { action: 'resend', email }
//     -> Regenerates and re-sends the code via Brevo.
//
//   POST /api/signup-verify { action: 'confirm', email, code }
//     -> Verifies the code against DynamoDB, then calls Cognito
//        AdminUpdateUserAttributes to set email_verified=true.
const crypto = require('crypto');
const {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  AdminUpdateUserAttributesCommand,
  ListUsersCommand
} = require('@aws-sdk/client-cognito-identity-provider');
const { REGION, USER_POOL_ID, send, parseBody } = require('./_auth');
const { generateCode, storeCode, getCode, markCodeUsed, deleteCode, bumpAttempts, sendCodeEmail, hashCode, MAX_ATTEMPTS } = require('./_brevo');

const cognito = new CognitoIdentityProviderClient({ region: REGION });

// FIX (duplicate accounts): this used to rely entirely on AdminCreateUser
// throwing UsernameExistsException to catch "this email already signed up".
// That only actually catches a duplicate if the User Pool's username
// attribute is configured to literally BE the email string. If the pool
// instead uses an auto-generated username and treats email only as a
// sign-in alias (a common Cognito setup), then Username: email never
// collides on a second attempt — Cognito just creates a brand new user
// with a new internal id ("sub") every time the same email signs up again.
// That is exactly what produced two separate "Niranjan Developer" rows
// with two different credit balances in the admin panel: two real,
// distinct Cognito users, both using webscratch99@gmail.com.
//
// Fix: explicitly search by the email ATTRIBUTE (not the username) before
// ever attempting to create anything. This catches a duplicate regardless
// of how the pool's username policy is configured.
async function findExistingUserByEmail(email) {
  const page = await cognito.send(new ListUsersCommand({
    UserPoolId: USER_POOL_ID,
    Filter: `email = "${email}"`,
    Limit: 1
  }));
  return (page.Users && page.Users[0]) || null;
}

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
    const password = body.password;
    const name = body.name || '';
    const referralCode = body.referral_code || null;
    if (!password) return send(res, 400, { error: { message: 'Password is required' } });

    console.log(`[SignupVerify] ── request received for email=${email}`);
    try {
      // Explicit duplicate check by email attribute — see
      // findExistingUserByEmail() comment above for why this is necessary
      // in addition to (not instead of) the UsernameExistsException catch
      // further down.
      const existing = await findExistingUserByEmail(email).catch(err => {
        console.warn(`[SignupVerify] ListUsers pre-check failed (continuing, AdminCreateUser try/catch below still guards):`, err.message || err);
        return null;
      });

      if (existing) {
        const existingAttrs = (existing.Attributes || []).reduce((acc, a) => { acc[a.Name] = a.Value; return acc; }, {});
        const alreadyVerified = existingAttrs.email_verified === 'true';

        if (alreadyVerified) {
          // A real, completed account already owns this email — block, don't duplicate.
          console.warn(`[SignupVerify] account already exists and is verified: ${email}`);
          return send(res, 400, { error: { message: 'An account with this email already exists.' } });
        }

        // Unverified leftover from a previous incomplete signup attempt
        // (they never entered the code, or it never arrived). Reuse this
        // SAME Cognito user instead of creating a second one — this is the
        // actual fix for the duplicate-account bug: every retry before
        // confirmation now lands on the same account instead of spawning
        // a new one with a new sub.
        console.log(`[SignupVerify] found unverified existing user for ${email} — reusing instead of creating a duplicate`);
        await cognito.send(new AdminSetUserPasswordCommand({
          UserPoolId: USER_POOL_ID,
          Username: existing.Username,
          Password: password,
          Permanent: true
        }));
        const updateAttrs = [];
        if (name) updateAttrs.push({ Name: 'name', Value: name });
        if (referralCode) updateAttrs.push({ Name: 'custom:referral_code', Value: referralCode });
        if (updateAttrs.length) {
          await cognito.send(new AdminUpdateUserAttributesCommand({
            UserPoolId: USER_POOL_ID,
            Username: existing.Username,
            UserAttributes: updateAttrs
          })).catch(err => console.warn('[SignupVerify] could not update attrs on reused user:', err.message || err));
        }

        const code = generateCode();
        await storeCode('signup_verify', email, code);
        await sendCodeEmail('signup_verify', email, code);
        console.log(`[SignupVerify] ✅ resent code to reused unverified account for ${email}`);
        return send(res, 200, { data: {} });
      }

      const attrs = [
        { Name: 'email', Value: email },
        { Name: 'email_verified', Value: 'false' }
      ];
      if (name) attrs.push({ Name: 'name', Value: name });
      if (referralCode) attrs.push({ Name: 'custom:referral_code', Value: referralCode });

      try {
        await cognito.send(new AdminCreateUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: email,
          UserAttributes: attrs,
          MessageAction: 'SUPPRESS', // <-- this is what stops Cognito sending its own email
          TemporaryPassword: crypto.randomBytes(12).toString('base64') + 'Aa1!'
        }));
        console.log(`[SignupVerify] Cognito user created (message suppressed) for ${email}`);
      } catch (createErr) {
        if (createErr.name === 'UsernameExistsException') {
          console.warn(`[SignupVerify] account already exists: ${email}`);
          return send(res, 400, { error: { message: 'An account with this email already exists.' } });
        }
        console.error(`[SignupVerify] AdminCreateUser FAILED for ${email}:`, createErr);
        throw createErr;
      }

      await cognito.send(new AdminSetUserPasswordCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        Password: password,
        Permanent: true
      }));
      console.log(`[SignupVerify] permanent password set for ${email}`);

      const code = generateCode();
      console.log(`[SignupVerify] code generated for ${email}, storing in DynamoDB`);
      await storeCode('signup_verify', email, code);

      console.log(`[SignupVerify] about to call sendCodeEmail() (Brevo) for ${email}`);
      await sendCodeEmail('signup_verify', email, code);
      console.log(`[SignupVerify] ✅ Brevo send completed successfully for ${email}`);

      return send(res, 200, { data: {} });
    } catch (err) {
      console.error(`[SignupVerify] ❌ request FAILED for ${email}:`, err);
      return send(res, 500, { error: { message: err.message || 'Could not create account' } });
    }
  }

  if (action === 'resend') {
    console.log(`[SignupVerify] ── resend received for email=${email}`);
    try {
      const code = generateCode();
      console.log(`[SignupVerify] resend code generated for ${email}, storing in DynamoDB`);
      await storeCode('signup_verify', email, code);
      await sendCodeEmail('signup_verify', email, code);
      console.log(`[SignupVerify] ✅ resend completed (Brevo) for ${email}`);
      return send(res, 200, { data: {} });
    } catch (err) {
      console.error(`[SignupVerify] ❌ resend FAILED for ${email}:`, err);
      return send(res, 500, { error: { message: err.message || 'Could not resend code' } });
    }
  }

  if (action === 'confirm') {
    const code = String(body.code || '').trim();
    if (!code) return send(res, 400, { error: { message: 'Verification code is required' } });

    console.log(`[SignupVerify] ── confirm received for email=${email}`);
    try {
      const record = await getCode('signup_verify', email);
      if (!record) {
        console.warn(`[SignupVerify] ❌ verification failed: no code record (or already used) for ${email}`);
        return send(res, 400, { error: { message: 'Invalid or expired code. Please request a new one.' } });
      }
      if (Date.now() > record.expiresAt) {
        console.warn(`[SignupVerify] ❌ verification failed: code expired for ${email}`);
        await deleteCode('signup_verify', email);
        return send(res, 400, { error: { message: 'This code has expired. Please request a new one.' } });
      }
      if ((record.attempts || 0) >= MAX_ATTEMPTS) {
        console.warn(`[SignupVerify] ❌ verification failed: too many attempts for ${email}`);
        await deleteCode('signup_verify', email);
        return send(res, 400, { error: { message: 'Too many incorrect attempts. Please request a new code.' } });
      }
      if (record.codeHash !== hashCode(code, email)) {
        await bumpAttempts('signup_verify', email);
        console.warn(`[SignupVerify] ❌ verification failed: code mismatch for ${email}`);
        return send(res, 400, { error: { message: 'Incorrect code. Please try again.' } });
      }

      await cognito.send(new AdminUpdateUserAttributesCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        UserAttributes: [{ Name: 'email_verified', Value: 'true' }]
      }));
      console.log(`[SignupVerify] ✅ verification success: email_verified=true set for ${email}`);

      await markCodeUsed('signup_verify', email);
      await deleteCode('signup_verify', email);
      return send(res, 200, { data: {} });
    } catch (err) {
      console.error(`[SignupVerify] ❌ confirm FAILED for ${email}:`, err);
      return send(res, 500, { error: { message: err.message || 'Could not verify email' } });
    }
  }

  return send(res, 400, { error: { message: 'Unsupported action' } });
};
