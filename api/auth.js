const crypto = require('crypto');
const { CognitoIdentityProviderClient, AdminGetUserCommand, ListUsersCommand, AdminDisableUserCommand, AdminDeleteUserCommand } = require('@aws-sdk/client-cognito-identity-provider');
const { DynamoDBClient, GetItemCommand, PutItemCommand, DeleteItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { REGION, USER_POOL_ID, APP_CLIENT_ID, send, parseBody } = require('./_auth');

const CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;
const COGNITO_URL = `https://cognito-idp.${REGION}.amazonaws.com/`;
const adminClient = new CognitoIdentityProviderClient({ region: REGION });
const ddb = new DynamoDBClient({ region: REGION });
const PROFILES_TABLE = process.env.TABLE_USERS || 'Users';

// ── AUTO-MERGE: Google sign-in creating a duplicate of an existing account ──
// Cognito Hosted UI federation creates a brand-new user (Username like
// "Google_<id>") for a Google sign-in, completely separate from any existing
// email/password account with the same email — by default it does NOT throw
// a conflict error or auto-link them, it just silently makes a second user.
// That second user gets a brand-new, empty DynamoDB profile row (10 credits,
// fresh referral code), while the person's real data sits under their old
// native account — looking exactly like "my credits got reset".
//
// Fix: every time someone completes a Google sign-in, check Cognito for any
// OTHER user (different sub, not itself a Google-federated user) sharing the
// same email. If found, merge that other account's profile data onto this
// session's profile row (keeping the higher credits, filling in any missing
// referral_code/name), then remove the old duplicate row and disable the old
// login so it can never silently happen again for this person.
async function autoMergeGoogleDuplicateIfAny(idToken) {
  try {
    const payloadB64 = String(idToken).split('.')[1];
    const claims = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
    const email = String(claims.email || '').trim().toLowerCase();
    const newSub = claims.sub;
    if (!email || !newSub) return;

    const page = await adminClient.send(new ListUsersCommand({
      UserPoolId: USER_POOL_ID,
      Filter: `email = "${email}"`,
      Limit: 10
    }));
    const others = (page.Users || []).filter(u => {
      const a = (u.Attributes || []).reduce((acc, x) => { acc[x.Name] = x.Value; return acc; }, {});
      return (a.sub || u.Username) !== newSub;
    });
    if (!others.length) return; // no duplicate — nothing to do

    // Prefer a native (non-Google) account as the one being merged IN;
    // if multiple, take the oldest (most likely the original).
    others.sort((a, b) => new Date(a.UserCreateDate) - new Date(b.UserCreateDate));
    const oldUser = others[0];
    const oldAttrs = (oldUser.Attributes || []).reduce((acc, x) => { acc[x.Name] = x.Value; return acc; }, {});
    const oldSub = oldAttrs.sub || oldUser.Username;
    if (!oldSub || oldSub === newSub) return;

    const [oldRowRes, newRowRes] = await Promise.all([
      ddb.send(new GetItemCommand({ TableName: PROFILES_TABLE, Key: marshall({ userId: oldSub }) })),
      ddb.send(new GetItemCommand({ TableName: PROFILES_TABLE, Key: marshall({ userId: newSub }) })),
    ]);
    const oldRow = oldRowRes.Item ? unmarshall(oldRowRes.Item) : null;
    const newRow = newRowRes.Item ? unmarshall(newRowRes.Item) : null;
    if (!oldRow) return; // nothing to merge in

    const oldCredits = parseFloat(oldRow.credits) || 0;
    const newCredits = parseFloat((newRow && newRow.credits)) || 0;
    const merged = Object.assign({}, oldRow, newRow || {});
    merged.credits = Math.max(oldCredits, newCredits);
    if (!merged.referral_code && oldRow.referral_code) merged.referral_code = oldRow.referral_code;
    if ((!merged.name || merged.name === 'User') && oldRow.name) merged.name = oldRow.name;
    merged.userId = newSub;
    merged.email = email;
    merged.updated_at = new Date().toISOString();

    await ddb.send(new PutItemCommand({ TableName: PROFILES_TABLE, Item: marshall(merged, { removeUndefinedValues: true }) }));
    await ddb.send(new DeleteItemCommand({ TableName: PROFILES_TABLE, Key: marshall({ userId: oldSub }) })).catch(() => {});
    await ddb.send(new DeleteItemCommand({ TableName: PROFILES_TABLE, Key: marshall({ id: oldSub }) })).catch(() => {}); // legacy-keyed row, if any

    // Remove the old duplicate login entirely so it can never be used again
    // to sign in and re-create another diverged profile, AND so it stops
    // showing up as a second "ghost" account with the same email in the
    // admin Users list. (Previously this only disabled the login, which left
    // a dead-but-visible duplicate Cognito user sitting in the pool forever —
    // exactly the "2 accounts with same email" symptom.) The person's data
    // and identity now live permanently under the Google-federated account
    // (newSub), so the old login is no longer needed at all.
    try {
      await adminClient.send(new AdminDeleteUserCommand({ UserPoolId: USER_POOL_ID, Username: oldUser.Username }));
    } catch (e) {
      console.warn('[Auth] Could not delete old duplicate login', oldUser.Username, ':', e.message);
      // Fallback: at least disable it so it can't be used to sign in again.
      try {
        await adminClient.send(new AdminDisableUserCommand({ UserPoolId: USER_POOL_ID, Username: oldUser.Username }));
      } catch (e2) { /* non-fatal */ }
    }

    console.log(`[Auth] Auto-merged Google sign-in duplicate for ${email}: old sub ${oldSub} (${oldCredits} credits) -> new sub ${newSub} (now ${merged.credits} credits); old login disabled.`);
  } catch (e) {
    console.warn('[Auth] autoMergeGoogleDuplicateIfAny failed (non-fatal):', e.message);
  }
}

// Actions that require SecretHash (App Client is configured with a secret).
// NOTE: SignUp / ConfirmSignUp / ResendConfirmationCode / ForgotPassword /
// ConfirmForgotPassword used to live here too, but those flows now go
// through api/signup-verify.js and api/forgot-password.js (custom Brevo
// codes) instead of Cognito's own email sending. InitiateAuth (login) is
// the only action this proxy still needs to support.
const SECRET_HASH_ACTIONS = {
  InitiateAuth: 'AuthParameters.USERNAME'
};

// Actions that go through the Cognito OAuth2 token endpoint directly.
// No SecretHash needed — the client_secret is sent in the POST body instead.
const OAUTH_TOKEN_ACTIONS = new Set(['GoogleTokenExchange']);

function computeSecretHash(username) {
  if (!CLIENT_SECRET) throw new Error('COGNITO_CLIENT_SECRET environment variable is required');
  return crypto
    .createHmac('sha256', CLIENT_SECRET)
    .update(String(username) + APP_CLIENT_ID)
    .digest('base64');
}

function resolveUsername(target, body) {
  if (target === 'InitiateAuth') {
    var params = body.AuthParameters || {};
    // USER_PASSWORD_AUTH uses USERNAME; REFRESH_TOKEN_AUTH needs the username passed
    // explicitly by the client (it isn't part of the refresh token itself).
    return params.USERNAME;
  }
  return body.Username;
}

// FIX (root cause of "Incorrect username or password" for real, correct
// passwords on migrated accounts): this used to pass the email the person
// typed straight to Cognito as USERNAME for USER_PASSWORD_AUTH. That only
// authenticates if the pool's literal username IS that email string.
// New signups get exactly that (see signup-verify.js's
// AdminCreateUser({ Username: email })), so login "just worked" for them —
// but migrated/legacy accounts (imported from Supabase, or anything not
// created through that exact path) can have a different real Cognito
// username, so USER_PASSWORD_AUTH with USERNAME=email rejects a completely
// correct password with a generic "incorrect username or password".
// This is the exact same class of bug already fixed in forgot-password.js's
// findUserByEmail() and signup-verify.js's findExistingUserByEmail().
//
// Fix: before attempting USER_PASSWORD_AUTH, look up the real Cognito
// username via ListUsers on the email attribute and sign in with THAT
// instead of the raw typed email. If no match is found (or the lookup
// itself fails), fall back to the typed value unchanged — so this never
// makes a working login flow fail, it only fixes the broken case.
async function resolveRealUsernameForLogin(typedUsername) {
  if (!typedUsername || typedUsername.indexOf('@') === -1) return typedUsername; // not an email, nothing to resolve
  try {
    const page = await adminClient.send(new ListUsersCommand({
      UserPoolId: USER_POOL_ID,
      Filter: `email = "${typedUsername}"`,
      Limit: 10
    }));
    const users = page.Users || [];
    if (!users.length) return typedUsername; // no match — let Cognito give its normal error
    const chosen = users.find(u => u.Enabled && u.UserStatus === 'CONFIRMED') || users.find(u => u.Enabled) || users[0];
    if (users.length > 1) {
      console.warn(`[Auth] ⚠️ multiple Cognito accounts for ${typedUsername} at login — chose Username=${chosen.Username} (Status=${chosen.UserStatus})`);
    }
    return chosen.Username;
  } catch (e) {
    console.warn('[Auth] resolveRealUsernameForLogin lookup failed (falling back to typed value):', e.message);
    return typedUsername;
  }
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
  try {
    const body = await parseBody(req);
    const target = body.target;
    if (!target || (!SECRET_HASH_ACTIONS[target] && !OAUTH_TOKEN_ACTIONS.has(target))) {
      throw new Error('Unsupported or missing auth target');
    }

    // ── Google OAuth token exchange ─────────────────────────────────────────
    // Frontend passes the authorization code it received from Cognito's Hosted UI.
    // We exchange it here (server-side) so CLIENT_SECRET is never exposed to the browser.
    if (target === 'GoogleTokenExchange') {
      const code = body.code;
      if (!code) throw new Error('Missing code');

      const cognitoDomain = process.env.COGNITO_DOMAIN;
      if (!cognitoDomain) throw new Error('Google sign-in is not configured on this server (COGNITO_DOMAIN missing).');
      if (!CLIENT_SECRET) throw new Error('COGNITO_CLIENT_SECRET environment variable is required');
      if (!APP_CLIENT_ID) throw new Error('COGNITO_APP_CLIENT_ID environment variable is required');

      // The redirect_uri must be byte-for-byte identical to the one used in the
      // /oauth2/authorize call. Trusting a client-supplied value here would let a
      // caller redirect the token exchange anywhere, so we always use our own
      // server-side env var instead of body.redirectUri.
      const redirectUri = process.env.COGNITO_REDIRECT_URI;
      if (!redirectUri) throw new Error('COGNITO_REDIRECT_URI environment variable is required');

      const tokenEndpoint = process.env.GOOGLE_TOKEN_URI || `https://${cognitoDomain}/oauth2/token`;
      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: APP_CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: redirectUri,
        code
      });

      const tokenResp = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString()
      });

      const tokenJson = await tokenResp.json().catch(function () { return {}; });

      if (!tokenResp.ok || tokenJson.error) {
        const errDesc = tokenJson.error_description || tokenJson.error || 'Token exchange failed';
        // When Google's email matches an existing Cognito email/password account that
        // isn't yet federated-linked, Cognito returns "Already found an entry for username".
        // Guide the user to sign in with their existing method instead.
        if (/already found|already linked|already exists|duplicate/i.test(errDesc)) {
          return send(res, 409, {
            error: {
              message: 'An account with this email already exists. Please sign in with your email and password.',
              code: 'ACCOUNT_EXISTS_WITH_EMAIL'
            }
          });
        }
        return send(res, tokenResp.status || 400, { error: { message: String(errDesc) } });
      }

      // Auto-merge: if this Google sign-in's email already has data sitting
      // under a different (older) account, fold it onto this session's
      // profile now — before the frontend ever loads the dashboard — so the
      // user never sees a reset-looking empty/10-credit account.
      if (tokenJson.id_token) {
        await autoMergeGoogleDuplicateIfAny(tokenJson.id_token);
      }

      // Normalize to PascalCase — matches the AuthenticationResult shape that
      // cognito-auth.js storeSession() / sb.auth.setSession() expect.
      return send(res, 200, {
        data: {
          AuthenticationResult: {
            AccessToken:  tokenJson.access_token,
            IdToken:      tokenJson.id_token,
            RefreshToken: tokenJson.refresh_token || null,
            TokenType:    tokenJson.token_type || 'Bearer',
            ExpiresIn:    tokenJson.expires_in  || 3600
          }
        }
      });
    }
    // ── End GoogleTokenExchange ─────────────────────────────────────────────

    const payload = Object.assign({}, body.payload || {});
    payload.ClientId = APP_CLIENT_ID;

    // Resolve the real Cognito username for password sign-ins BEFORE anything
    // else touches `payload` — see resolveRealUsernameForLogin() above.
    // REFRESH_TOKEN_AUTH is untouched: it doesn't carry an email, and
    // resolveRealUsernameForLogin() only ever changes actual email-looking
    // values anyway.
    if (target === 'InitiateAuth' && payload.AuthFlow === 'USER_PASSWORD_AUTH' && payload.AuthParameters && payload.AuthParameters.USERNAME) {
      const typed = payload.AuthParameters.USERNAME;
      const real = await resolveRealUsernameForLogin(typed);
      if (real !== typed) {
        console.log(`[Auth] login: resolved typed username "${typed}" -> real Cognito username "${real}"`);
      }
      payload.AuthParameters = Object.assign({}, payload.AuthParameters, { USERNAME: real });
    }

    const username = resolveUsername(target, payload);
    if (!username) throw new Error('Username is required to compute SecretHash');
    const secretHash = computeSecretHash(username);

    if (target === 'InitiateAuth') {
      payload.AuthParameters = Object.assign({}, payload.AuthParameters, { SECRET_HASH: secretHash });
    } else {
      payload.SecretHash = secretHash;
    }

    const resp = await fetch(COGNITO_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.' + target
      },
      body: JSON.stringify(payload)
    });
    const json = await resp.json().catch(function () { return {}; });
    if (!resp.ok || json.__type) {
      // On a failed password sign-in, check if this is a legacy account imported
      // from Supabase that's stuck in FORCE_CHANGE_PASSWORD status — Cognito won't
      // allow USER_PASSWORD_AUTH for those, but won't say why either.
      if (target === 'InitiateAuth' && payload.AuthFlow === 'USER_PASSWORD_AUTH') {
        try {
          const userInfo = await adminClient.send(new AdminGetUserCommand({
            UserPoolId: USER_POOL_ID,
            Username: username
          }));
          if (userInfo.UserStatus === 'FORCE_CHANGE_PASSWORD' || userInfo.UserStatus === 'RESET_REQUIRED') {
            return send(res, 200, { data: null, legacyAccount: true });
          }
        } catch (lookupErr) {
          // user truly doesn't exist or lookup failed — fall through to normal error
        }
      }
      return send(res, resp.status || 400, { error: json });
    }
    return send(res, 200, { data: json });
  } catch (err) {
    return send(res, 400, { error: { message: err.message || 'Auth request failed' } });
  }
};
