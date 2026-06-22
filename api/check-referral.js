// Public, UNAUTHENTICATED referral-code lookup.
//
// Bug this fixes: the signup form's live "✅ valid code" / "❌ doesn't
// match" check was calling sb.from('profiles').eq('referral_code', code)
// through cognito-auth.js -> /api/data, but /api/data requires a valid
// Cognito Bearer token (see verifyToken() at the top of the handler in
// api/data.js). A person filling out the signup form has no session yet
// (they're not logged in), so that request ALWAYS failed with "Not
// authenticated" — meaning the form showed "doesn't match any account"
// for every referral code, real or not, even valid ones like RC: 10233784.
//
// Fix: this endpoint does the same lookup (scan Users table, match
// referral_code) but with no auth requirement, since the only data it
// returns is a name and email — the same info a referral code is meant to
// reveal anyway. It is read-only and never returns credits, ids, or
// anything sensitive.
//
//   POST /api/check-referral { code: "12345678" }
//     -> { data: { name, email } }   if a profile with that referral_code exists
//     -> { data: null }              if no match
const { DynamoDBClient, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { unmarshall } = require('@aws-sdk/util-dynamodb');
const { send, parseBody } = require('./_auth');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const TABLE_USERS = process.env.TABLE_USERS || 'Users';
const ddb = new DynamoDBClient({ region: REGION });

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST') return send(res, 405, { error: { message: 'Method not allowed' } });

  let body;
  try {
    body = await parseBody(req);
  } catch (err) {
    return send(res, 400, { error: { message: 'Invalid request body' } });
  }

  const code = String(body.code || '').trim();
  if (!/^\d{6,8}$/.test(code)) {
    return send(res, 400, { error: { message: 'Referral code must be 6-8 digits' } });
  }

  try {
    // Users table has no GSI on referral_code, so this scans + filters —
    // same approach /api/data's readItems() falls back to for non-key
    // lookups. The Users table is small enough for this to be cheap and
    // it only runs while someone is actively typing a code on the signup
    // form (debounced 600ms client-side).
    const scanned = await ddb.send(new ScanCommand({ TableName: TABLE_USERS }));
    const items = (scanned.Items || []).map(unmarshall);
    const match = items.find(item => String(item.referral_code || '') === code);

    if (!match) return send(res, 200, { data: null, error: null });

    return send(res, 200, {
      data: { name: match.name || null, email: match.email || null },
      error: null
    });
  } catch (err) {
    console.error('[CheckReferral] lookup failed:', err);
    return send(res, 500, { error: { message: 'Could not look up referral code' } });
  }
};
