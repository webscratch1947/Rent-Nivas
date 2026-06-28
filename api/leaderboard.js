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
  res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=120');
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
        let credits;
        const prevIsLegacy = prev._isLegacy;
        const currIsLegacy = row._isLegacy;
        if (!currIsLegacy && prevIsLegacy) {
          credits = parseFloat(row.credits) || 0;
        } else if (currIsLegacy && !prevIsLegacy) {
          credits = parseFloat(prev.credits) || 0;
        } else {
          const prevTime = prev.updated_at || prev.created_at || '';
          const currTime = row.updated_at || row.created_at || '';
          credits = currTime > prevTime
            ? parseFloat(row.credits) || 0
            : parseFloat(prev.credits) || 0;
        }
        byId[uid] = {
          ...prev,
          ...row,
          id: uid,
          credits,
          name: (prev.name && prev.name.trim()) ? prev.name : (row.name || ''),
          avatar_url: prev.avatar_url || row.avatar_url || null,
          _isLegacy: false,
        };
      }
    }

    const merged = Object.values(byId);
    merged.sort((a, b) => (parseFloat(b.credits) || 0) - (parseFloat(a.credits) || 0));

    const limit = 300;
    const top = merged.slice(0, limit);

    const result = top.map((row, idx) => ({
      rank: idx + 1,
      id: row.id || '',
      name: row.name || '',
      avatar_url: row.avatar_url || null,
      credits: parseFloat(row.credits) || 0,
      xp: parseInt(row.xp || '0', 10),
    }));

    return send(res, 200, { data: result, error: null });
  } catch (err) {
    console.error('[Leaderboard] public fetch failed:', err);
    return send(res, 500, { data: null, error: 'Could not fetch leaderboard' });
  }
};
