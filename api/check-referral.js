const { DynamoDBClient, GetItemCommand, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { send, parseBody } = require('./_auth');

const REGION = process.env.AWS_REGION || 'eu-north-1';
const TABLE_REFERRALS = process.env.TABLE_REFERRALS || 'Referrals';
const TABLE_USERS     = process.env.TABLE_USERS     || 'Users';
const ddb = new DynamoDBClient({ region: REGION });

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST') return send(res, 405, { error: { message: 'Method not allowed' } });

  let body;
  try { body = await parseBody(req); }
  catch (err) { return send(res, 400, { error: { message: 'Invalid request body' } }); }

  const raw  = String(body.code || '').trim();
  const code = raw.toUpperCase(); // for hex codes
  const codeRaw = raw;            // for numeric codes stored as-is

  if (!raw || raw.length < 4 || raw.length > 12) {
    return send(res, 400, { error: { message: 'Invalid referral code format' } });
  }

  try {
    // 1. Check Referrals table (uppercased key)
    const refResult = await ddb.send(new GetItemCommand({
      TableName: TABLE_REFERRALS,
      Key: marshall({ referralId: code })
    }));
    if (refResult.Item) {
      const item = unmarshall(refResult.Item);
      if (item.active === false) return send(res, 200, { data: null, error: null });
      return send(res, 200, { data: { name: item.userName || null, email: item.userEmail || null }, error: null });
    }

    // 2. Check Referrals table with raw (numeric codes)
    if (codeRaw !== code) {
      const refResult2 = await ddb.send(new GetItemCommand({
        TableName: TABLE_REFERRALS,
        Key: marshall({ referralId: codeRaw })
      }));
      if (refResult2.Item) {
        const item = unmarshall(refResult2.Item);
        if (item.active === false) return send(res, 200, { data: null, error: null });
        return send(res, 200, { data: { name: item.userName || null, email: item.userEmail || null }, error: null });
      }
    }

    // 3. Fallback: scan Users table, match referral_code case-insensitively
    const scanned = await ddb.send(new ScanCommand({ TableName: TABLE_USERS }));
    const items = (scanned.Items || []).map(i => unmarshall(i));
    const match = items.find(i => {
      const stored = String(i.referral_code || '').trim();
      return stored.toUpperCase() === code || stored === codeRaw;
    });
    if (!match) return send(res, 200, { data: null, error: null });
    return send(res, 200, { data: { name: match.name || null, email: match.email || null }, error: null });

  } catch (err) {
    console.error('[CheckReferral] lookup failed:', err);
    return send(res, 500, { error: { message: 'Could not look up referral code' } });
  }
};
