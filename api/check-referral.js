// Public, UNAUTHENTICATED referral-code lookup.
//
// Uses the NEW Referrals table (partition key: referralId = the code itself).
// A direct GetItem replaces the old Users table full-table scan — much faster.
//
//   POST /api/check-referral { code: "ABCD1234" }
//     -> { data: { name, email } }   if found and active
//     -> { data: null }              if no match or inactive
//
// Read-only. Returns only name + email — nothing sensitive.

const { DynamoDBClient, GetItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { send, parseBody } = require('./_auth');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const TABLE_REFERRALS = process.env.TABLE_REFERRALS || 'Referrals';
const TABLE_USERS     = process.env.TABLE_USERS     || 'Users';
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

  // Normalise: codes may arrive in any case or with whitespace
  const raw  = String(body.code || '').trim();
  const code = raw.toUpperCase();

  if (!code || code.length < 4 || code.length > 12) {
    return send(res, 400, { error: { message: 'Invalid referral code format' } });
  }

  try {
    // ── Primary: look up in the new Referrals table ──────────────────────────
    const refResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_REFERRALS,
      Key: marshall({ referralId: code })
    }));

    if (refResult.Item) {
      const item = unmarshall(refResult.Item);
      // active defaults to true if the field is missing (older records)
      if (item.active === false) return send(res, 200, { data: null, error: null });
      return send(res, 200, {
        data: { name: item.userName || null, email: item.userEmail || null },
        error: null
      });
    }

    // ── Fallback: code might still only exist in Users table (legacy) ────────
    // This handles users whose Referrals record hasn't been created yet (they
    // haven't opened the Referral panel since the migration) but whose
    // referral_code field in Users is already in use on a signup form.
    try {
      // DynamoDB has no GSI on referral_code in Users, so we need a scan.
      // This is intentionally the slow fallback path — it will become
      // irrelevant once every user's Referrals record exists.
      const { ScanCommand } = require('@aws-sdk/client-dynamodb');
      const scanned = await ddb.send(new ScanCommand({ TableName: TABLE_USERS }));
      const items = (scanned.Items || []).map(i => unmarshall(i));
      const match = items.find(i => String(i.referral_code || '').toUpperCase() === code);
      if (!match) return send(res, 200, { data: null, error: null });
      return send(res, 200, {
        data: { name: match.name || null, email: match.email || null },
        error: null
      });
    } catch (_) {
      return send(res, 200, { data: null, error: null });
    }

  } catch (err) {
    console.error('[CheckReferral] lookup failed:', err);
    return send(res, 500, { error: { message: 'Could not look up referral code' } });
  }
};
