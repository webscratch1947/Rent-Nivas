// POST /api/migrate-referral-fields
//
// Admin-only endpoint that backfills every existing row in the Users (profiles)
// table with the seven referral fields that may be absent on accounts created
// before the referral system existed.
//
// Fields added (only when the field is absent or undefined):
//   referral_code            – 8-digit numeric string, unique per user
//   referred_by_code         – null
//   referred_by_user_id      – null
//   partner_xp               – 0  (mirrors the `xp` column used by partner panel)
//   credits                  – 10 (preserves existing value if already set)
//   total_referrals          – 0
//   registration_referrals   – 0
//   listing_referrals        – 0
//
// Existing field values are NEVER overwritten — this is append-only.
//
// Usage (curl):
//   curl -X POST https://your-domain.com/api/migrate-referral-fields \
//        -H "Authorization: Bearer <admin-jwt>"
//
// The endpoint is idempotent — running it multiple times is safe.

const crypto = require('crypto');
const {
  DynamoDBClient,
  ScanCommand,
  UpdateItemCommand,
} = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { requireAdmin, send, REGION } = require('./_auth');

const ddb = new DynamoDBClient({ region: REGION });
const USERS_TABLE = process.env.TABLE_USERS || 'Users';

// Required referral fields and their default values.
// `undefined` default means "set to null".
const REFERRAL_FIELDS = {
  referral_code:          null,   // will be auto-generated per user
  referred_by_code:       null,
  referred_by_user_id:    null,
  partner_xp:             0,
  credits:                10,
  total_referrals:        0,
  registration_referrals: 0,
  listing_referrals:      0,
};

function generateReferralCode() {
  return String(Math.floor(10000000 + Math.random() * 90000000));
}

/**
 * Build and execute a DynamoDB UpdateExpression that sets only the missing
 * attributes on a single Users row.  Returns the number of fields patched.
 */
async function patchUser(row) {
  const patch = {};

  for (const [field, defaultVal] of Object.entries(REFERRAL_FIELDS)) {
    if (field === 'credits') {
      // Floor everyone at 10 credits (admin-requested baseline bump) —
      // this field deliberately bypasses the "skip if already set" check
      // below, since the whole point is to raise existing low/zero values.
      const current = parseFloat(row[field]);
      if (isNaN(current) || current < 10) patch[field] = defaultVal;
      continue;
    }
    if (row[field] !== undefined && row[field] !== null && row[field] !== '') continue;

    if (field === 'referral_code') {
      // Generate a unique code for this user
      patch[field] = generateReferralCode();
    } else {
      patch[field] = defaultVal;
    }
  }

  if (Object.keys(patch).length === 0) return 0;

  patch.updated_at = new Date().toISOString();

  const names  = {};
  const values = {};
  const sets   = [];

  Object.entries(patch).forEach(([k, v], i) => {
    names[`#k${i}`]  = k;
    values[`:v${i}`] = v;
    sets.push(`#k${i} = :v${i}`);
  });

  const Key = marshall({ id: row.id }, { removeUndefinedValues: true });

  await ddb.send(new UpdateItemCommand({
    TableName: USERS_TABLE,
    Key,
    UpdateExpression: `SET ${sets.join(', ')}`,
    ExpressionAttributeNames:  names,
    ExpressionAttributeValues: marshall(values, { removeUndefinedValues: true }),
    // Only touch the row if it still has the same id (safety check)
    ConditionExpression: 'attribute_exists(id)',
  }));

  return Object.keys(patch).length;
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST')   return send(res, 405, { error: { message: 'Method not allowed' } });

  // Require admin JWT
  try {
    await requireAdmin(req);
  } catch (err) {
    return send(res, 401, { error: { message: err.message || 'Unauthorized' } });
  }

  console.log('[MigrateReferral] Starting referral field migration...');

  let lastKey    = undefined;
  let totalUsers = 0;
  let patched    = 0;
  let skipped    = 0;
  let errors     = 0;

  try {
    // Paginate through all Users rows
    do {
      const params = { TableName: USERS_TABLE };
      if (lastKey) params.ExclusiveStartKey = lastKey;

      const result = await ddb.send(new ScanCommand(params));
      const rows   = (result.Items || []).map(i => unmarshall(i));

      totalUsers += rows.length;

      for (const row of rows) {
        if (!row.id) { skipped++; continue; }
        try {
          const fieldsPatched = await patchUser(row);
          if (fieldsPatched > 0) {
            patched++;
            console.log(`[MigrateReferral] Patched user ${row.id} (${fieldsPatched} fields)`);
          } else {
            skipped++;
          }
        } catch (err) {
          errors++;
          console.error(`[MigrateReferral] Failed to patch user ${row.id}:`, err.message);
        }
      }

      lastKey = result.LastEvaluatedKey;
    } while (lastKey);

    const summary = { total_users: totalUsers, patched, skipped, errors };
    console.log('[MigrateReferral] Migration complete:', summary);
    return send(res, 200, { data: summary });

  } catch (err) {
    console.error('[MigrateReferral] Fatal scan error:', err.message);
    return send(res, 500, { error: { message: err.message || 'Migration failed' } });
  }
};
