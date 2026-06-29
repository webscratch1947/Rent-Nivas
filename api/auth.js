const crypto = require('crypto');
const { CognitoIdentityProviderClient, AdminGetUserCommand } = require('@aws-sdk/client-cognito-identity-provider');
const { REGION, USER_POOL_ID, APP_CLIENT_ID, send, parseBody } = require('./_auth');

const CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;
const COGNITO_URL = `https://cognito-idp.${REGION}.amazonaws.com/`;
const adminClient = new CognitoIdentityProviderClient({ region: REGION });

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
      const redirectUri = body.redirectUri;
      if (!code || !redirectUri) throw new Error('Missing code or redirectUri');

      const cognitoDomain = process.env.COGNITO_DOMAIN || 'eu-north-1gm7zi2xvq.auth.eu-north-1.amazoncognito.com';
      if (!cognitoDomain) throw new Error('Google sign-in is not configured on this server (COGNITO_DOMAIN missing).');
      if (!CLIENT_SECRET) throw new Error('COGNITO_CLIENT_SECRET environment variable is required');

      const tokenEndpoint = `https://${cognitoDomain}/oauth2/token`;
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
