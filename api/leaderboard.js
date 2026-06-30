// Public, UNAUTHENTICATED leaderboard endpoint.
//
// GET /api/leaderboard
//   -> { data: [ { rank, id, name, avatar_url, credits, xp }, ... ] }
//
// HOW IT WORKS:
// 1. Scan DynamoDB for all known users (with credits, names, etc)
// 2. List ALL Cognito users (ALL statuses — confirmed, unconfirmed, etc)
// 3. Cross-check: any DynamoDB row with no Cognito match = deleted user = auto-delete + exclude
// 4. Cross-check: any Cognito user with no DynamoDB row = new user who hasn't logged in yet
//    → show them with their name from Cognito + default 10 credits

const { DynamoDBClient, ScanCommand, DeleteItemCommand } = require('@aws-sdk/client-dynamodb');
const { unmarshall, marshall } = require('@aws-sdk/util-dynamodb');
const { CognitoIdentityProviderClient, ListUsersCommand } = require('@aws-sdk/client-cognito-identity-provider');

const REGION       = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const TABLE_USERS  = process.env.TABLE_USERS || 'Users';
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const DEFAULT_CREDITS = 10; // credits every new user starts with

const ddb     = new DynamoDBClient({ region: REGION });
const cognito = new CognitoIdentityProviderClient({ region: REGION });

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.end(JSON.stringify(payload));
}

// ── Fetch ALL Cognito users — every status (CONFIRMED, UNCONFIRMED, etc) ────
// Returns a Map of sub → { sub, name, email } so we have name/email too
async function fetchAllCognitoUsers() {
  const byId = new Map(); // sub UUID → { sub, name, email }
  let paginationToken;
  do {
    const cmd = new ListUsersCommand({
      UserPoolId: USER_POOL_ID,
      Limit: 60,
      // NO Filter — all users regardless of status
      ...(paginationToken ? { PaginationToken: paginationToken } : {}),
    });
    const page = await cognito.send(cmd);
    for (const u of page.Users || []) {
      const attrs = (u.Attributes || []).reduce((acc, a) => { acc[a.Name] = a.Value; return acc; }, {});
      const sub = attrs.sub;
      if (!sub) continue;
      byId.set(sub, {
        sub,
        name:  attrs.name || attrs.given_name || '',
        email: attrs.email || '',
      });
    }
    paginationToken = page.PaginationToken;
  } while (paginationToken);
  return byId;
}

// ── Silently delete an orphaned DynamoDB row (fire-and-forget) ──────────────
async function deleteOrphanRow(userId) {
  try {
    await ddb.send(new DeleteItemCommand({
      TableName: TABLE_USERS,
      Key: marshall({ userId }),
    }));
    console.log('[Leaderboard] Auto-deleted orphaned DynamoDB row:', userId);
  } catch (err) {
    console.warn('[Leaderboard] Could not delete orphan row:', userId, err.message);
  }
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.statusCode = 204;
    res.end();
    return;
  }
  if (req.method !== 'GET') return send(res, 405, { error: 'Method not allowed' });

  try {
    // Run DynamoDB scan + Cognito list in PARALLEL for speed
    const [scanned, cognitoUsers] = await Promise.all([
      ddb.send(new ScanCommand({ TableName: TABLE_USERS, ConsistentRead: true })),
      fetchAllCognitoUsers(),
    ]);

    // ── Build DynamoDB map, de-duplicating legacy rows ───────────────────
    const rawRows = (scanned.Items || []).map(item => {
      const r = unmarshall(item);
      const isLegacy = !Object.prototype.hasOwnProperty.call(r, 'userId') &&
                        Object.prototype.hasOwnProperty.call(r, 'id');
      const effectiveId = r.userId || r.id || '';
      return Object.assign({}, r, { id: effectiveId, _isLegacy: isLegacy });
    });

    const byId = {};
    for (const row of rawRows) {
      const uid = String(row.id || '');
      if (!uid) continue;
      if (!byId[uid]) {
        byId[uid] = row;
      } else {
        const prev = byId[uid];
        const prevCredits = parseFloat(prev.credits) || 0;
        const currCredits = parseFloat(row.credits) || 0;
        const credits = Math.max(prevCredits, currCredits);
        const prevIsLegacy = prev._isLegacy;
        const currIsLegacy = row._isLegacy;
        const baseRow = (!currIsLegacy && prevIsLegacy) ? row
                      : (currIsLegacy && !prevIsLegacy) ? prev
                      : ((row.updated_at || row.created_at || '') > (prev.updated_at || prev.created_at || '') ? row : prev);
        byId[uid] = {
          ...prev, ...baseRow,
          id: uid,
          credits,
          name: (prev.name && prev.name.trim()) ? prev.name : (row.name || ''),
          avatar_url: prev.avatar_url || row.avatar_url || null,
          _isLegacy: false,
        };
      }
    }

    // ── FILTER: Remove ghost rows + orphans (deleted from Cognito) ───────
    const orphansToDelete = [];
    const realUsers = [];

    for (const row of Object.values(byId)) {
      const uid = String(row.id || '');
      if (!uid || uid.includes('@')) continue; // skip ghost/email-key rows

      if (!cognitoUsers.has(uid)) {
        // No matching Cognito account → user was deleted → auto-remove
        orphansToDelete.push(uid);
        console.log('[Leaderboard] Orphan detected (deleted from Cognito):', uid);
        continue;
      }

      realUsers.push(row);
    }

    // Fire-and-forget: clean up orphan DynamoDB rows in background
    if (orphansToDelete.length > 0) {
      Promise.all(orphansToDelete.map(deleteOrphanRow)).catch(() => {});
    }

    // ── ADD: Cognito users who have no DynamoDB row yet ──────────────────
    // These are people who signed up but never logged in.
    // Show them with default credits so they appear on the leaderboard.
    const dbIds = new Set(realUsers.map(r => r.id));
    for (const [sub, cogUser] of cognitoUsers) {
      if (dbIds.has(sub)) continue; // already in DynamoDB → skip

      // Skip if no name and no email (shouldn't happen but be safe)
      if (!cogUser.name && !cogUser.email) continue;

      realUsers.push({
        id:         sub,
        name:       cogUser.name  || '',
        email:      cogUser.email || '',
        credits:    DEFAULT_CREDITS,
        xp:         0,
        avatar_url: null,
        _cognitoOnly: true, // flag for debugging only
      });
    }

    // ── Sort by credits descending ────────────────────────────────────────
    realUsers.sort((a, b) => (parseFloat(b.credits) || 0) - (parseFloat(a.credits) || 0));

    const top = realUsers.slice(0, 300);

    const result = top.map((row, idx) => {
      const rawName = (row.name || '').trim();
      const effectiveName = (rawName && rawName.toLowerCase() !== 'user')
        ? rawName
        : (row.email ? row.email.split('@')[0] : '');
      return {
        rank:       idx + 1,
        id:         row.id || '',
        name:       effectiveName,
        avatar_url: row.avatar_url || null,
        credits:    parseFloat(row.credits) || 0,
        xp:         parseInt(row.xp || '0', 10),
        email:      row.email || '',
      };
    });

    return send(res, 200, { data: result, error: null });
  } catch (err) {
    console.error('[Leaderboard] fetch failed:', err);
    return send(res, 500, { data: null, error: 'Could not fetch leaderboard' });
  }
};
