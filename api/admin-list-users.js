const { CognitoIdentityProviderClient, ListUsersCommand } = require('@aws-sdk/client-cognito-identity-provider');
const { DynamoDBClient, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { unmarshall } = require('@aws-sdk/util-dynamodb');
const { REGION, USER_POOL_ID, send, requireAdmin } = require('./_auth');

const cognito = new CognitoIdentityProviderClient({ region: REGION });
const ddb = new DynamoDBClient({ region: REGION });

function attrs(list) {
  return (list || []).reduce((acc, a) => { acc[a.Name] = a.Value; return acc; }, {});
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'GET' && req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
  try {
    await requireAdmin(req);
    const users = [];
    let PaginationToken;
    do {
      const page = await cognito.send(new ListUsersCommand({ UserPoolId: USER_POOL_ID, Limit: 60, PaginationToken }));
      (page.Users || []).forEach(u => {
        const a = attrs(u.Attributes);
        users.push({
          id: a.sub || u.Username,
          username: u.Username,
          email: a.email || '',
          name: a.name || '',
          email_confirmed_at: a.email_verified === 'true' ? u.UserLastModifiedDate : null,
          created_at: u.UserCreateDate,
          last_sign_in_at: u.UserLastModifiedDate,
          status: u.UserStatus,
          disabled: !u.Enabled
        });
      });
      PaginationToken = page.PaginationToken;
    } while (PaginationToken);

    try {
      const profiles = await ddb.send(new ScanCommand({ TableName: process.env.TABLE_USERS || 'Users' }));
      const byId = new Map((profiles.Items || []).map(item => {
        const p = unmarshall(item);
        // The Users table's real partition key is "userId" — older rows
        // (migrated before that was discovered) may still carry a legacy
        // "id" attribute instead. Accept either so every account merges.
        const key = p.userId || p.id;
        return [String(key), p];
      }));
      users.forEach(u => {
        const profile = byId.get(String(u.id));
        if (profile) {
          const { userId, id, ...rest } = profile; // keep u.id as the Cognito sub
          Object.assign(u, rest);
        }
      });
    } catch (err) {
      console.warn('[RentNivas] Could not merge Users table profiles:', err.message || err);
    }

    send(res, 200, { users });
  } catch (err) {
    console.error('[RentNivas] admin-list-users failed:', err);
    send(res, /Admin access|required|authorization|token/i.test(err.message || '') ? 401 : 500, { error: err.message || 'Failed to list users' });
  }
};
