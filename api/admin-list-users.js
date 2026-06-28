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
      const allProfiles = (profiles.Items || []).map(item => unmarshall(item));

      // Build TWO lookup maps: by userId/id AND by email
      // This is critical for migrated accounts where the DynamoDB userId
      // (old Supabase UUID) differs from the Cognito sub.
      // Without email-based fallback, admin sees wrong credits and
      // "Edit Credits" creates a ghost row keyed by the Cognito sub.
      const byId    = new Map();
      const byEmail = new Map();
      for (const p of allProfiles) {
        const key = String(p.userId || p.id || '');
        if (key) byId.set(key, p);
        const em = String(p.email || '').toLowerCase().trim();
        if (em) {
          // If multiple rows share the same email, prefer the one with higher credits
          const existing = byEmail.get(em);
          if (!existing || (parseFloat(p.credits) || 0) > (parseFloat(existing.credits) || 0)) {
            byEmail.set(em, p);
          }
        }
      }

      users.forEach(u => {
        // Try matching by Cognito sub first, then fall back to email
        const profile = byId.get(String(u.id)) || byEmail.get(String(u.email).toLowerCase().trim());
        if (profile) {
          const profileId = profile.userId || profile.id;
          // CRITICAL: use the DynamoDB row's own userId as the canonical id
          // for all admin operations (credits edit, ban, etc.) so they always
          // hit the correct existing row instead of creating a ghost row.
          const { userId, id, ...rest } = profile;
          Object.assign(u, rest);
          u.id = profileId || u.id; // override with DynamoDB key so Edit Credits hits the right row
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
