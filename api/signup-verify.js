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
//        AdminUpdateUserAttributes to set email_verified=true,
//        and writes pending_referral_code to the user's DynamoDB profile.
const crypto = require('crypto');
const {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminGetUserCommand,
  AdminSetUserPasswordCommand,
  AdminUpdateUserAttributesCommand,
  ListUsersCommand
} = require('@aws-sdk/client-cognito-identity-provider');
const { DynamoDBClient, UpdateItemCommand, GetItemCommand, PutItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { REGION, USER_POOL_ID, send, parseBody } = require('./_auth');
const { generateCode, storeCode, getCode, markCodeUsed, deleteCode, bumpAttempts, sendCodeEmail, hashCode, MAX_ATTEMPTS } = require('./_brevo');

const cognito = new CognitoIdentityProviderClient({ region: REGION });
const ddb = new DynamoDBClient({ region: REGION });
const TABLE_USERS = process.env.TABLE_USERS || 'Users';
const TABLE_CODES = process.env.TABLE_VERIFICATION_CODES || 'VerificationCodes';

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

// Store a pending referral code in the VerificationCodes record so it can
// be read back during the 'confirm' step. Uses the same pk key as storeCode.
async function storePendingReferralCode(email, referralCode) {
  if (!referralCode) return;
  const pk = `signup_verify#${String(email).toLowerCase()}`;
  try {
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_CODES,
      Key: marshall({ pk }),
      UpdateExpression: 'SET pendingReferralCode = :rc',
      ExpressionAttributeValues: marshall({ ':rc': String(referralCode) })
    }));
  } catch (err) {
    // Non-fatal — referral code will fall back to profile lookup
    console.warn('[SignupVerify] Could not store pendingReferralCode:', err.message || err);
  }
}

// Read back the pending referral code stored during 'request'.
async function getPendingReferralCode(email) {
  const pk = `signup_verify#${String(email).toLowerCase()}`;
  try {
    const result = await ddb.send(new GetItemCommand({
      TableName: TABLE_CODES,
      Key: marshall({ pk })
    }));
    if (!result.Item) return null;
    const item = unmarshall(result.Item);
    return item.pendingReferralCode || null;
  } catch (err) {
    console.warn('[SignupVerify] Could not read pendingReferralCode:', err.message || err);
    return null;
  }
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
        // NOTE: Only update name — do NOT try to set custom:referral_code as a
        // Cognito attribute. That attribute is not declared in the User Pool
        // schema, so Cognito rejects it with a ValidationException. Instead,
        // the referral code is stashed via storePendingReferralCode() (see
        // below) and picked up server-side by /api/referrals during
        // process_registration.
        const updateAttrs = [];
        if (name) updateAttrs.push({ Name: 'name', Value: name });
        if (updateAttrs.length) {
          await cognito.send(new AdminUpdateUserAttributesCommand({
            UserPoolId: USER_POOL_ID,
            Username: existing.Username,
            UserAttributes: updateAttrs
          })).catch(err => console.warn('[SignupVerify] could not update attrs on reused user:', err.message || err));
        }

        const code = generateCode();
        await storeCode('signup_verify', email, code);
        // Store the referral code alongside the verification record so it
        // can be retrieved in the 'confirm' step.
        if (referralCode) await storePendingReferralCode(email, referralCode);
        await sendCodeEmail('signup_verify', email, code);
        console.log(`[SignupVerify] ✅ resent code to reused unverified account for ${email}`);
        return send(res, 200, { data: {} });
      }

      // NOTE: Do NOT include custom:referral_code in the Cognito user
      // attributes — the attribute does not exist in this User Pool's schema
      // and Cognito throws a ValidationException when you try to set it.
      // The referral code is stored separately in DynamoDB (see below).
      const attrs = [
        { Name: 'email', Value: email },
        { Name: 'email_verified', Value: 'false' }
      ];
      if (name) attrs.push({ Name: 'name', Value: name });

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
      // Store the referral code alongside the verification record so it
      // can be retrieved in the 'confirm' step without needing a Cognito
      // custom attribute.
      if (referralCode) await storePendingReferralCode(email, referralCode);

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
      // BUG FIX: storeCode() does a full PutItem (not an Update) on the same
      // pk as the referral code we stashed via storePendingReferralCode() —
      // so every resend was silently wiping out the referral attribution
      // before the user ever finished verifying. Read it out first, then
      // re-attach it after the fresh code is stored.
      const priorRecord = await getCode('signup_verify', email).catch(() => null);
      const carriedReferralCode = priorRecord && priorRecord.pendingReferralCode;

      const code = generateCode();
      console.log(`[SignupVerify] resend code generated for ${email}, storing in DynamoDB`);
      await storeCode('signup_verify', email, code);
      if (carriedReferralCode) {
        await storePendingReferralCode(email, carriedReferralCode);
        console.log(`[SignupVerify] carried pendingReferralCode (${carriedReferralCode}) across resend for ${email}`);
      }
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

      // NOTE: referral-code generation/ownership and "who referred this user"
      // are no longer handled here. Both now live in the new referral system
      // (api/referrals.js, backed by the Referrals table):
      //   - a user's own code is created lazily via POST /api/referrals
      //     action='ensure' the first time they open the referral panel.
      //   - the pending code captured at signup (stored in VerificationCodes
      //     by storePendingReferralCode above) is read by
      //     POST /api/referrals action='process_registration' on first
      //     login, via getPendingReferralCode as a fallback.

      await markCodeUsed('signup_verify', email);
      await deleteCode('signup_verify', email);

      // ── Read pending referral code from the verify record ───────────────────
      let pendingReferralCode = null;
      try {
        const vcRaw = await ddb.send(new GetItemCommand({ TableName: TABLE_CODES, Key: marshall({ pk: 'signup_verify#' + email }) }));
        if (vcRaw.Item) {
          const vcItem = unmarshall(vcRaw.Item);
          pendingReferralCode = vcItem.pendingReferralCode || null;
        }
      } catch (_) {}

      // ── Create DynamoDB user row with 10 credits ─────────────────────────
      // Do this here so the row always exists with credits=10 when the user
      // first logs in. The frontend upsert is a fallback but can silently fail.
      try {
        const cogUser = await cognito.send(new AdminGetUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: email,
        }));
        const subAttr = (cogUser.UserAttributes || []).find(a => a.Name === 'sub');
        const nameAttr = (cogUser.UserAttributes || []).find(a => a.Name === 'name');
        const userId = subAttr && subAttr.Value;
        if (userId) {
          // Only create if row doesn't already exist
          const existing = await ddb.send(new GetItemCommand({
            TableName: TABLE_USERS,
            Key: marshall({ userId }),
          }));
          if (!existing.Item) {
            await ddb.send(new PutItemCommand({
              TableName: TABLE_USERS,
              Item: marshall({
                userId,
                name: (nameAttr && nameAttr.Value) || email.split('@')[0] || 'User',
                email: email.toLowerCase(),
                credits: 10,
                xp: 0,
                partner_xp: 0,
                daily_streak_day: 0,
                daily_streak_claimed_at: null,
                referral_code: null,
                referred_by_code: null,
                pending_referral_code: pendingReferralCode || null,
                created_at: new Date().toISOString(),
                verified: false,
              }, { removeUndefinedValues: true }),
              ConditionExpression: 'attribute_not_exists(userId)',
            })).catch(() => {}); // ignore if row was created concurrently
            console.log('[SignupVerify] ✅ DynamoDB user row created with 10 credits for', email);
          } else {
            console.log('[SignupVerify] DynamoDB row already exists for', email, '— skipping creation');
            // If row exists but pending_referral_code not set, patch it in
            if (referralCode) {
              await ddb.send(new UpdateItemCommand({
                TableName: TABLE_USERS,
                Key: marshall({ userId }),
                UpdateExpression: 'SET pending_referral_code = if_not_exists(pending_referral_code, :rc)',
                ExpressionAttributeValues: marshall({ ':rc': pendingReferralCode }),
              })).catch(() => {});
            }
          }
        }
      } catch (dbErr) {
        console.warn('[SignupVerify] Could not create DynamoDB row (non-fatal):', dbErr.message || dbErr);
      }

      return send(res, 200, { data: {} });
    } catch (err) {
      console.error(`[SignupVerify] ❌ confirm FAILED for ${email}:`, err);
      return send(res, 500, { error: { message: err.message || 'Could not verify email' } });
    }
  }

  return send(res, 400, { error: { message: 'Unsupported action' } });
};
