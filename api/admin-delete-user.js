const { CognitoIdentityProviderClient, AdminDeleteUserCommand, ListUsersCommand } = require('@aws-sdk/client-cognito-identity-provider');
const { DynamoDBClient, DeleteItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall } = require('@aws-sdk/util-dynamodb');
const { REGION, USER_POOL_ID, send, parseBody, requireAdmin } = require('./_auth');

const cognito = new CognitoIdentityProviderClient({ region: REGION });
const ddb = new DynamoDBClient({ region: REGION });

async function findUsernameBySub(sub) {
  const page = await cognito.send(new ListUsersCommand({ UserPoolId: USER_POOL_ID, Filter: `sub = "${sub}"`, Limit: 1 }));
  return page.Users && page.Users[0] && page.Users[0].Username;
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST' && req.method !== 'DELETE') return send(res, 405, { error: 'Method not allowed' });
  try {
    await requireAdmin(req);
    const body = await parseBody(req);
    const targetUserId = body.targetUserId || body.userId || body.id;
    const targetUsername = body.targetUsername || body.username || body.email || await findUsernameBySub(targetUserId);
    if (!targetUserId && !targetUsername) throw new Error('targetUserId or targetUsername is required');
    if (!targetUsername) throw new Error('Cognito user not found for targetUserId');

    await cognito.send(new AdminDeleteUserCommand({ UserPoolId: USER_POOL_ID, Username: targetUsername }));
    if (targetUserId) {
      await ddb.send(new DeleteItemCommand({ TableName: 'Users', Key: marshall({ id: targetUserId }) })).catch(err => {
        console.warn('[RentNivas] Users delete skipped:', err.message || err);
      });
    }
    send(res, 200, { ok: true });
  } catch (err) {
    console.error('[RentNivas] admin-delete-user failed:', err);
    send(res, /Admin access|required|authorization|token/i.test(err.message || '') ? 401 : 500, { error: err.message || 'Failed to delete user' });
  }
};
