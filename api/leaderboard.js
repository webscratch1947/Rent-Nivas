// Public, UNAUTHENTICATED leaderboard endpoint.
//
// Why this exists: the original leaderboard used sb.rpc('get_leaderboard')
// via /api/data which requires a valid Cognito Bearer token. When a user's
// session expired, or the leaderboard polled before auth was confirmed, the
// fetch returned "Not authenticated" and the leaderboard appeared empty or
// broken. Making the leaderboard public (no auth required) fixes this because
// leaderboard data — names, credits, ranks — is intentionally public info.
//
//   GET /api/leaderboard
//     -> { data: [ { rank, id, name, avatar_url, credits, xp }, ... ] }
const { DynamoDBClient, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { unmarshall } = require('@aws-sdk/util-dynamodb');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const TABLE_USERS = process.env.TABLE_USERS || 'Users';
const ddb = new DynamoDBClient({ region: REGION });

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.end(JSON.stringify(payload));
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
    const scanned = await ddb.send(new ScanCommand({ TableName: TABLE_USERS }));
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
        // Always take the HIGHEST credits value across all duplicate rows —
        // avoids picking a stale/older row just because it has a newer timestamp.
        const prevCredits = parseFloat(prev.credits) || 0;
        const currCredits = parseFloat(row.credits) || 0;
        const credits = Math.max(prevCredits, currCredits);
        // For the rest of the fields, prefer the non-legacy (userId-keyed) row,
        // falling back to the most-recently-updated row for name/avatar.
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

    // ── FILTER OUT GHOST ROWS ──────────────────────────────────────────────
    // Ghost rows are created when signup-verify.js used cognitoUser.Username
    // (the email string) as the DynamoDB key instead of the real Cognito sub UUID.
    // These rows have userId = "user@example.com" — detectable because a valid
    // Cognito sub is always a UUID (no @ symbol).
    // Also filter rows with zero credits that have no name and no email since
    // those are partial rows created by race conditions and have no display data.
    const realUsers = merged.filter(row => {
      const uid = String(row.id || '');
      // If the key looks like an email address, it's a ghost row
      if (uid.includes('@')) return false;
      // If it's clearly a UUID-ish string or short ID, it's a real user
      return true;
    });
    realUsers.sort((a, b) => (parseFloat(b.credits) || 0) - (parseFloat(a.credits) || 0));

    const limit = 300;
    const top = realUsers.slice(0, limit);

    const result = top.map((row, idx) => {
      // Derive a display name server-side so users with blank names are not
      // filtered out as "Anonymous" on the frontend. If name is blank/missing,
      // fall back to the email prefix (part before @). This matches exactly
      // what the frontend displayName() function does, but done here so the
      // email field is available for the fallback even though the API response
      // doesn't expose the raw email address for privacy.
      const rawName = (row.name || '').trim();
      const effectiveName = (rawName && rawName.toLowerCase() !== 'user')
        ? rawName
        : (row.email ? row.email.split('@')[0] : '');
      return {
        rank: idx + 1,
        id: row.id || '',
        name: effectiveName,
        avatar_url: row.avatar_url || null,
        credits: parseFloat(row.credits) || 0,
        xp: parseInt(row.xp || '0', 10),
        email: row.email || '',
      };
    });

    return send(res, 200, { data: result, error: null });
  } catch (err) {
    console.error('[Leaderboard] public fetch failed:', err);
    return send(res, 500, { data: null, error: 'Could not fetch leaderboard' });
  }
};
