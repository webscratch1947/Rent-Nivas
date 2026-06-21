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
      // FIX: the Users table's actual DynamoDB partition key is "userId",
      // not "id" — this was always deleting the wrong (non-existent) key,
      // so the DynamoDB profile row never actually got removed. The Cognito
      // account was deleted, but the orphaned profile row stayed behind
      // forever. If that same email signed up again later, a fresh Cognito
      // user (new sub) was created with no link to the old leftover row —
      // which then showed up looking like a duplicate/ghost account.
      await ddb.send(new DeleteItemCommand({ TableName: process.env.TABLE_USERS || 'Users', Key: marshall({ userId: targetUserId }) })).catch(err => {
        console.warn('[RentNivas] Users delete skipped:', err.message || err);
      });
    }
    send(res, 200, { ok: true });
  } catch (err) {
    console.error('[RentNivas] admin-delete-user failed:', err);
    send(res, /Admin access|required|authorization|token/i.test(err.message || '') ? 401 : 500, { error: err.message || 'Failed to delete user' });
  }
};
