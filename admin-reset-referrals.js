// Admin endpoint — wipes ALL referral data from Users + VerificationCodes tables.
// Call once to fix existing corrupted data, then the new system takes over.
//
// POST /api/admin-reset-referrals
// Headers: Authorization: Bearer <admin-secret>
// Body: { confirm: "RESET_ALL_REFERRALS" }   ← safety check
//
// What it does:
//   1. Scans EVERY row in the Users table and removes:
//        referral_code, referred_by_code, pending_referral_code,
//        total_referrals, registration_referrals, listing_referrals
//   2. Scans EVERY row in VerificationCodes and removes:
//        pending_referral_code
// After this runs, users get fresh referral codes generated at next login.

const { DynamoDBClient, ScanCommand, UpdateItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { send, parseBody } = require('./_auth');

const ddb = new DynamoDBClient({ region: process.env.AWS_REGION || 'eu-north-1' });
const TABLE_USERS = process.env.TABLE_USERS || 'Users';
const TABLE_CODES = process.env.TABLE_VERIFICATION_CODES || 'VerificationCodes';
const ADMIN_SECRET = process.env.ADMIN_SECRET || process.env.SESSION_SECRET || '';

async function scanAll(TableName) {
  const rows = [];
  let ExclusiveStartKey;
  do {
    const res = await ddb.send(new ScanCommand({ TableName, ExclusiveStartKey }));
    (res.Items || []).forEach(i => rows.push(unmarshall(i)));
    ExclusiveStartKey = res.LastEvaluatedKey;
  } while (ExclusiveStartKey);
  return rows;
}

async function removeFieldsFromRow(TableName, key, fields) {
  const removes = fields.map((f, i) => `#f${i}`).join(', ');
  const names = {};
  fields.forEach((f, i) => { names[`#f${i}`] = f; });
  try {
    await ddb.send(new UpdateItemCommand({
      TableName,
      Key: marshall(key),
      UpdateExpression: `REMOVE ${removes}`,
      ExpressionAttributeNames: names,
    }));
    return true;
  } catch (e) {
    return false;
  }
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST') return send(res, 405, { error: { message: 'Method not allowed' } });

  // Auth check
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (!ADMIN_SECRET || token !== ADMIN_SECRET) {
    return send(res, 401, { error: { message: 'Unauthorized' } });
  }

  let body;
  try { body = await parseBody(req); } catch { return send(res, 400, { error: { message: 'Bad body' } }); }

  if ((body.confirm || '').trim() !== 'RESET_ALL_REFERRALS') {
    return send(res, 400, { error: { message: 'Send { confirm: "RESET_ALL_REFERRALS" } to proceed.' } });
  }

  try {
    // ── Users table ──────────────────────────────────────────────────────────
    const userFields = ['referral_code','referred_by_code','pending_referral_code',
                        'total_referrals','registration_referrals','listing_referrals'];
    const users = await scanAll(TABLE_USERS);
    let usersUpdated = 0, usersFailed = 0;
    for (const row of users) {
      const key = row.userId ? { userId: row.userId } : { id: row.id };
      if (!key.userId && !key.id) continue;
      const hasSome = userFields.some(f => row[f] !== undefined);
      if (!hasSome) continue; // skip rows that already have none of these fields
      const ok = await removeFieldsFromRow(TABLE_USERS, key, userFields);
      if (ok) usersUpdated++; else usersFailed++;
    }

    // ── VerificationCodes table ───────────────────────────────────────────────
    const vcRows = await scanAll(TABLE_CODES);
    let vcUpdated = 0, vcFailed = 0;
    for (const row of vcRows) {
      if (!row.pk) continue;
      if (row.pending_referral_code === undefined) continue;
      const ok = await removeFieldsFromRow(TABLE_CODES, { pk: row.pk }, ['pending_referral_code']);
      if (ok) vcUpdated++; else vcFailed++;
    }

    console.log('[ResetReferrals] Done — users:', usersUpdated, 'failed:', usersFailed,
      '| codes:', vcUpdated, 'failed:', vcFailed);

    return send(res, 200, {
      ok: true,
      users: { scanned: users.length, updated: usersUpdated, failed: usersFailed },
      verificationCodes: { scanned: vcRows.length, updated: vcUpdated, failed: vcFailed },
      message: 'All referral data wiped. Users will get fresh codes on next login.'
    });
  } catch (err) {
    console.error('[ResetReferrals] Failed:', err);
    return send(res, 500, { error: { message: err.message || 'Reset failed' } });
  }
};
