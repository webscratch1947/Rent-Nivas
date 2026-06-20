const crypto = require('crypto');
const { CognitoIdentityProviderClient, AdminGetUserCommand } = require('@aws-sdk/client-cognito-identity-provider');
const { REGION, USER_POOL_ID, APP_CLIENT_ID, send, parseBody } = require('./_auth');

const CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET;
const COGNITO_URL = `https://cognito-idp.${REGION}.amazonaws.com/`;
const adminClient = new CognitoIdentityProviderClient({ region: REGION });

// Actions that require SecretHash (App Client is configured with a secret)
const SECRET_HASH_ACTIONS = {
  SignUp: 'Username',
  InitiateAuth: 'AuthParameters.USERNAME',
  ForgotPassword: 'Username',
  ConfirmForgotPassword: 'Username',
  ConfirmSignUp: 'Username',
  ResendConfirmationCode: 'Username'
};

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
    if (!target || !SECRET_HASH_ACTIONS[target]) {
      throw new Error('Unsupported or missing auth target');
    }

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
