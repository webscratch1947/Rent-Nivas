// Public, UNAUTHENTICATED leaderboard endpoint.
//
// GET /api/leaderboard
//   -> { data: [ { rank, id, name, avatar_url, credits, xp }, ... ] }
//
// KEY FIX: Before returning, we cross-check every DynamoDB user against
// Cognito. If a user was deleted directly from Cognito (bypassing admin panel),
// their DynamoDB row stays behind as a ghost. We detect and skip those here,
// AND auto-delete the orphaned DynamoDB row so it never comes back.

const { DynamoDBClient, ScanCommand, DeleteItemCommand } = require('@aws-sdk/client-dynamodb');
const { unmarshall, marshall } = require('@aws-sdk/util-dynamodb');
const { CognitoIdentityProviderClient, ListUsersCommand } = require('@aws-sdk/client-cognito-identity-provider');

const REGION     = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const TABLE_USERS = process.env.TABLE_USERS || 'Users';
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'eu-north-1_GM7Zi2xvq';

const ddb     = new DynamoDBClient({ region: REGION });
const cognito = new CognitoIdentityProviderClient({ region: REGION });

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.end(JSON.stringify(payload));
}

// ── Fetch ALL Cognito user subs in one paginated sweep ──────────────────────
// Returns a Set of sub (UUID) strings — the ground truth of who really exists.
async function fetchAllCognitoSubs() {
  const subs = new Set();
  let paginationToken;
  do {
    const cmd = new ListUsersCommand({
      UserPoolId: USER_POOL_ID,
      Limit: 60,
      ...(paginationToken ? { PaginationToken: paginationToken } : {}),
    });
    const page = await cognito.send(cmd);
    for (const u of page.Users || []) {
      const subAttr = (u.Attributes || []).find(a => a.Name === 'sub');
      if (subAttr) subs.add(subAttr.Value);
    }
    paginationToken = page.PaginationToken;
  } while (paginationToken);
  return subs;
}

// ── Silently delete an orphaned DynamoDB row ────────────────────────────────
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
    const [scanned, cognitoSubs] = await Promise.all([
      ddb.send(new ScanCommand({ TableName: TABLE_USERS })),
      fetchAllCognitoSubs(),
    ]);

    const rawRows = (scanned.Items || []).map(item => {
      const r = unmarshall(item);
      const isLegacy = !Object.prototype.hasOwnProperty.call(r, 'userId') &&
                        Object.prototype.hasOwnProperty.call(r, 'id');
      const effectiveId = r.userId || r.id || '';
      return Object.assign({}, r, { id: effectiveId, _isLegacy: isLegacy });
    });

    // De-duplicate: prefer non-legacy (userId-keyed) row's credits
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
          ...prev,
          ...baseRow,
          id: uid,
          credits,
          name: (prev.name && prev.name.trim()) ? prev.name : (row.name || ''),
          avatar_url: prev.avatar_url || row.avatar_url || null,
          _isLegacy: false,
        };
      }
    }

    const merged = Object.values(byId);

    // ── FILTER 1: Remove ghost rows (email-as-key rows) ──────────────────
    // ── FILTER 2: Cross-check vs Cognito — skip + auto-delete orphans ────
    const orphansToDelete = [];
    const realUsers = merged.filter(row => {
      const uid = String(row.id || '');

      // Ghost row: key is an email address, not a UUID
      if (uid.includes('@')) return false;

      // Skip rows with no meaningful ID
      if (!uid) return false;

      // ── THE KEY FIX: verify this user still exists in Cognito ──
      if (!cognitoSubs.has(uid)) {
        // This DynamoDB row has no matching Cognito account — it's an orphan.
        // Queue it for silent deletion so it never haunts the leaderboard again.
        orphansToDelete.push(uid);
        console.log('[Leaderboard] Orphan detected (no Cognito account):', uid);
        return false; // exclude from leaderboard
      }

      return true;
    });

    // Fire-and-forget: delete orphan rows in background (don't await — keep response fast)
    if (orphansToDelete.length > 0) {
      Promise.all(orphansToDelete.map(deleteOrphanRow)).catch(() => {});
    }

    // ── FILTER 3: Skip rows where name AND email are both empty ──────────
    const visibleUsers = realUsers.filter(row => {
      const rawName = (row.name || '').trim();
      const email   = (row.email || '').trim();
      return (rawName && rawName.toLowerCase() !== 'user') || email;
    });

    visibleUsers.sort((a, b) => (parseFloat(b.credits) || 0) - (parseFloat(a.credits) || 0));

    const top = visibleUsers.slice(0, 300);

    const result = top.map((row, idx) => {
      const rawName = (row.name || '').trim();
      const effectiveName = (rawName && rawName.toLowerCase() !== 'user')
        ? rawName
        : (row.email ? row.email.split('@')[0] : '');
      return {
        rank: idx + 1,
        id:   row.id || '',
        name: effectiveName,
        avatar_url: row.avatar_url || null,
        credits: parseFloat(row.credits) || 0,
        xp:      parseInt(row.xp || '0', 10),
        email:   row.email || '',
      };
    });

    return send(res, 200, { data: result, error: null });
  } catch (err) {
    console.error('[Leaderboard] fetch failed:', err);
    return send(res, 500, { data: null, error: 'Could not fetch leaderboard' });
  }
};
