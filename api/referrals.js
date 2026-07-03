// api/referrals.js
//
// Referral System API — fully rebuilt on a dedicated "Referrals" DynamoDB
// table (partition key: referralId, a String — the code itself).
//
// This replaces the OLD referral system entirely, which stored referral
// state as extra fields directly on the Users/profiles table
// (referral_code, referred_by_code, referred_by_user_id, total_referrals,
// registration_referrals, listing_referrals, pending_referral_code) plus
// two RPCs inside api/data.js (process_registration_referral,
// award_referral_reward) and a standalone api/check-referral.js endpoint.
// None of that old bookkeeping exists anymore — everything referral-related
// now lives in one Referrals item per code:
//
//   {
//     referralId:              "12345678"        (PK — the code itself)
//     ownerId:                 <Cognito sub of the code's owner>
//     ownerName, ownerEmail
//     totalReferrals, registrationReferrals, listingReferrals
//     history: [
//       { userId, name, email, type: 'registration' | 'listing',
//         houseId?, rewardType: 'xp' | 'credits', rewardAmount, createdAt }
//     ]
//     createdAt, updatedAt
//   }
//
// Reward logic is UNCHANGED from the old system:
//   registration → +15 XP if the referrer is an approved partner, else +0.50 credits
//   listing      → +10 XP if the referrer is an approved partner, else +0.50 credits
//
// Note: houses.referral_code / houses.referral_reward_given on the
// Houses/Properties table are NOT part of the old referral system's
// bookkeeping — they are the operational record of which code was entered
// when a specific listing was created, and are still needed here to award
// the listing reward exactly once per listing.
//
// Actions (all POST /api/referrals with JSON body { action, ... }):
//   'ensure'               (auth)   -> get-or-create the caller's own referral code
//   'stats'                (auth)   -> get the caller's own code + counters + history
//   'validate'             (public) -> { code } -> { name, email } | null
//   'process_registration' (auth)   -> { code? } -> reward the referrer once, idempotent
//   'award_listing'        (auth)   -> { houseId } -> reward the referrer once, idempotent

const { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { send, parseBody, verifyToken } = require('./_auth');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const ddb = new DynamoDBClient({ region: REGION });

const TABLE_REFERRALS = process.env.TABLE_REFERRALS || 'Referrals';
const TABLE_USERS = process.env.TABLE_USERS || 'Users';
const TABLE_HOUSES = process.env.TABLE_HOUSES || 'Properties';
const TABLE_PARTNER_APPLICATIONS = process.env.TABLE_PARTNER_APPLICATIONS || 'PartnerApplications';
const TABLE_VERIFICATION_CODES = process.env.TABLE_VERIFICATION_CODES || 'VerificationCodes';

function generateCode() {
  return String(Math.floor(10000000 + Math.random() * 90000000));
}

function isValidCodeFormat(code) {
  return /^[0-9]{6,10}$/.test(String(code || '').trim());
}

// ── Users table helpers ──────────────────────────────────────────────────
// Users rows are keyed by "userId", but some legacy accounts were created
// before that rename and are still keyed by "id" — mirror the same
// fallback used elsewhere in this codebase so referral lookups/updates
// never silently miss an existing account.
async function getUserRow(userId) {
  const got = await ddb.send(new GetItemCommand({ TableName: TABLE_USERS, Key: marshall({ userId }) }));
  if (got.Item) return unmarshall(got.Item);
  const legacy = await ddb.send(new GetItemCommand({ TableName: TABLE_USERS, Key: marshall({ id: userId }) }));
  return legacy.Item ? unmarshall(legacy.Item) : null;
}

async function updateUserRow(userId, patch) {
  const now = new Date().toISOString();
  const values = Object.assign({}, patch, { updated_at: now });
  const names = {};
  const exprValues = {};
  const sets = [];
  Object.entries(values).forEach(([k, v], i) => {
    names[`#k${i}`] = k;
    exprValues[`:v${i}`] = v;
    sets.push(`#k${i} = :v${i}`);
  });
  try {
    await ddb.send(new UpdateItemCommand({
      TableName: TABLE_USERS,
      Key: marshall({ userId }),
      UpdateExpression: `SET ${sets.join(', ')}`,
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: marshall(exprValues, { removeUndefinedValues: true }),
      ConditionExpression: 'attribute_exists(userId)',
    }));
    return true;
  } catch (err) {
    const code = err && (err.name || err.__type || '');
    if (/ConditionalCheckFailedException/i.test(code)) {
      // Fall back to the legacy "id"-keyed row.
      try {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_USERS,
          Key: marshall({ id: userId }),
          UpdateExpression: `SET ${sets.join(', ')}`,
          ExpressionAttributeNames: names,
          ExpressionAttributeValues: marshall(exprValues, { removeUndefinedValues: true }),
          ConditionExpression: 'attribute_exists(id)',
        }));
        return true;
      } catch (legacyErr) {
        console.warn('[Referrals] updateUserRow legacy fallback failed:', legacyErr.message);
        return false;
      }
    }
    console.warn('[Referrals] updateUserRow failed:', err.message);
    return false;
  }
}

async function hasPartnerAccess(userId) {
  try {
    const scanned = await ddb.send(new ScanCommand({ TableName: TABLE_PARTNER_APPLICATIONS }));
    const rows = (scanned.Items || []).map(i => unmarshall(i));
    return rows.some(r => (r.user_id === userId || r.userId === userId) && r.status === 'accepted');
  } catch (err) {
    console.error('[Referrals] hasPartnerAccess check failed:', err.message);
    return false;
  }
}

// ── Referrals table helpers ──────────────────────────────────────────────
async function getReferralByCode(code) {
  const got = await ddb.send(new GetItemCommand({ TableName: TABLE_REFERRALS, Key: marshall({ referralId: String(code) }) }));
  return got.Item ? unmarshall(got.Item) : null;
}

async function getReferralByOwner(ownerId) {
  // Small table (one item per user who has ever opened the referral panel) —
  // a scan is fine here, same tradeoff already used elsewhere in this app
  // (hasPartnerAccess, the old check-referral.js) for tables of this size.
  const scanned = await ddb.send(new ScanCommand({ TableName: TABLE_REFERRALS }));
  const rows = (scanned.Items || []).map(i => unmarshall(i));
  return rows.find(r => r.ownerId === ownerId) || null;
}

async function findHistoryEntry(userId, type) {
  const scanned = await ddb.send(new ScanCommand({ TableName: TABLE_REFERRALS }));
  const rows = (scanned.Items || []).map(i => unmarshall(i));
  for (const row of rows) {
    const history = Array.isArray(row.history) ? row.history : [];
    if (history.some(h => h.userId === userId && h.type === type)) return row;
  }
  return null;
}

async function createReferralItem(ownerId, ownerName, ownerEmail) {
  // Try a handful of random codes until we find one that isn't taken —
  // PutItem's ConditionExpression guarantees we never clobber an existing
  // code even if two requests race for the same random value.
  for (let attempt = 0; attempt < 8; attempt++) {
    const code = generateCode();
    const now = new Date().toISOString();
    const item = {
      referralId: code,
      ownerId,
      ownerName: ownerName || '',
      ownerEmail: ownerEmail || '',
      totalReferrals: 0,
      registrationReferrals: 0,
      listingReferrals: 0,
      history: [],
      createdAt: now,
      updatedAt: now,
    };
    try {
      await ddb.send(new PutItemCommand({
        TableName: TABLE_REFERRALS,
        Item: marshall(item, { removeUndefinedValues: true }),
        ConditionExpression: 'attribute_not_exists(referralId)',
      }));
      return item;
    } catch (err) {
      const code2 = err && (err.name || err.__type || '');
      if (/ConditionalCheckFailedException/i.test(code2)) continue; // code taken, retry
      throw err;
    }
  }
  throw new Error('Could not generate a unique referral code — please try again');
}

async function ensureReferralItem(ownerId, ownerName, ownerEmail) {
  const existing = await getReferralByOwner(ownerId);
  if (existing) return existing;
  return createReferralItem(ownerId, ownerName, ownerEmail);
}

async function appendHistoryAndIncrement(referralId, entry, counterField) {
  const now = new Date().toISOString();
  await ddb.send(new UpdateItemCommand({
    TableName: TABLE_REFERRALS,
    Key: marshall({ referralId }),
    UpdateExpression: `SET history = list_append(if_not_exists(history, :empty), :entry), updatedAt = :now ADD totalReferrals :one, ${counterField} :one`,
    ExpressionAttributeValues: marshall({
      ':entry': [entry],
      ':empty': [],
      ':now': now,
      ':one': 1,
    }, { removeUndefinedValues: true }),
  }));
}

async function applyRewardToOwner(ownerId, type) {
  const isPartner = await hasPartnerAccess(ownerId);
  const ownerRow = await getUserRow(ownerId);
  if (!ownerRow) throw new Error(`Referrer profile not found for id=${ownerId}`);

  const currentXP = parseInt(ownerRow.xp || ownerRow.partner_xp || '0', 10) || 0;
  const currentCredits = parseFloat(ownerRow.credits || '0') || 0;

  let rewardType, rewardAmount, patch;
  const xpAmount = type === 'registration' ? 15 : 10;
  if (isPartner) {
    rewardType = 'xp';
    rewardAmount = xpAmount;
    patch = { xp: currentXP + xpAmount, partner_xp: currentXP + xpAmount };
  } else {
    rewardType = 'credits';
    rewardAmount = 0.50;
    patch = { credits: Math.round((currentCredits + 0.50) * 100) / 100 };
  }

  const applied = await updateUserRow(ownerId, patch);
  if (!applied) throw new Error(`Could not apply reward to referrer ${ownerId}`);

  console.log(`[Referrals] Awarded ${rewardType}:${rewardAmount} to owner ${ownerId} (${type}, partner=${isPartner})`);
  return { rewardType, rewardAmount, isPartner };
}

// ── HTTP handler ──────────────────────────────────────────────────────────
module.exports = async (req, res) => {
  if (req.method !== 'POST') return send(res, 405, { error: { message: 'Method not allowed' } });

  let body;
  try {
    body = await parseBody(req);
  } catch (err) {
    return send(res, 400, { error: { message: 'Invalid JSON body' } });
  }

  const action = body && body.action;

  try {
    // ── validate: public, no auth required ──────────────────────────────
    if (action === 'validate') {
      const code = String((body && body.code) || '').trim();
      if (!isValidCodeFormat(code)) return send(res, 200, { data: null });
      const item = await getReferralByCode(code);
      if (!item) return send(res, 200, { data: null });
      return send(res, 200, { data: { name: item.ownerName || '', email: item.ownerEmail || '' } });
    }

    // Everything else requires a valid, authenticated caller.
    const claims = await verifyToken(req);
    const userId = claims.sub;
    const userEmail = String(claims.email || '').trim().toLowerCase();

    if (action === 'ensure') {
      const ownerRow = await getUserRow(userId);
      const item = await ensureReferralItem(userId, ownerRow && ownerRow.name, ownerRow ? ownerRow.email : claims.email);
      return send(res, 200, { data: { referralId: item.referralId } });
    }

    if (action === 'stats') {
      const ownerRow = await getUserRow(userId);
      const item = await ensureReferralItem(userId, ownerRow && ownerRow.name, ownerRow ? ownerRow.email : claims.email);
      return send(res, 200, {
        data: {
          referralId: item.referralId,
          totalReferrals: item.totalReferrals || 0,
          registrationReferrals: item.registrationReferrals || 0,
          listingReferrals: item.listingReferrals || 0,
          history: Array.isArray(item.history) ? item.history : [],
        },
      });
    }

    if (action === 'process_registration') {
      let code = String((body && body.code) || '').trim();

      // Fallback: referral code stashed by api/signup-verify.js in
      // VerificationCodes at signup time, used when the client didn't have
      // (or lost) the code by the time the user first logs in.
      if (!code && userEmail) {
        try {
          const vcRes = await ddb.send(new GetItemCommand({
            TableName: TABLE_VERIFICATION_CODES,
            Key: marshall({ pk: `signup_verify#${userEmail}` }),
          }));
          if (vcRes.Item) {
            const vcItem = unmarshall(vcRes.Item);
            if (vcItem.pendingReferralCode) code = String(vcItem.pendingReferralCode).trim();
          }
        } catch (e) {
          console.warn('[Referrals] Could not read pendingReferralCode from VerificationCodes:', e.message);
        }
      }

      if (!code) return send(res, 200, { data: { processed: false, reason: 'no_code' } });

      // Idempotency guard: a user may only ever trigger one registration reward.
      const already = await findHistoryEntry(userId, 'registration');
      if (already) return send(res, 200, { data: { processed: false, reason: 'already_processed' } });

      const referral = await getReferralByCode(code);
      if (!referral || referral.ownerId === userId) {
        return send(res, 200, { data: { processed: false, reason: 'referrer_not_found' } });
      }

      const reward = await applyRewardToOwner(referral.ownerId, 'registration');

      const newUserRow = await getUserRow(userId);
      await appendHistoryAndIncrement(referral.referralId, {
        userId,
        name: (newUserRow && newUserRow.name) || '',
        email: (newUserRow && newUserRow.email) || claims.email || '',
        type: 'registration',
        rewardType: reward.rewardType,
        rewardAmount: reward.rewardAmount,
        createdAt: new Date().toISOString(),
      }, 'registrationReferrals');

      // Clear the pending code so it cannot be replayed on re-registration.
      if (userEmail) {
        try {
          await ddb.send(new UpdateItemCommand({
            TableName: TABLE_VERIFICATION_CODES,
            Key: marshall({ pk: `signup_verify#${userEmail}` }),
            UpdateExpression: 'REMOVE pendingReferralCode',
          }));
        } catch (e) { /* non-fatal */ }
      }

      console.log(`[Referrals] Registration referral processed: new_user=${userId} referrer=${referral.ownerId}`);
      return send(res, 200, { data: { processed: true, referrer_id: referral.ownerId, reward } });
    }

    if (action === 'award_listing') {
      const houseId = String((body && body.houseId) || '').trim();
      if (!houseId) return send(res, 200, { data: { awarded: false, reason: 'no_house_id' } });

      const houseGot = await ddb.send(new GetItemCommand({ TableName: TABLE_HOUSES, Key: marshall({ propertyId: houseId }) }));
      const house = houseGot.Item ? unmarshall(houseGot.Item) : null;
      if (!house) return send(res, 200, { data: { awarded: false, reason: 'house_not_found' } });
      if (house.referral_reward_given) return send(res, 200, { data: { awarded: false, reason: 'already_awarded' } });

      const refCode = String(house.referral_code || '').trim();
      if (!refCode) return send(res, 200, { data: { awarded: false, reason: 'no_referral_code' } });

      const referral = await getReferralByCode(refCode);
      if (!referral) return send(res, 200, { data: { awarded: false, reason: 'referrer_not_found' } });
      if (referral.ownerId === house.owner_id || referral.ownerId === userId) {
        return send(res, 200, { data: { awarded: false, reason: 'self_referral' } });
      }

      // Mark the listing first so a duplicate call can never double-award.
      try {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_HOUSES,
          Key: marshall({ propertyId: houseId }),
          UpdateExpression: 'SET referral_reward_given = :true',
          ConditionExpression: 'attribute_not_exists(referral_reward_given) OR referral_reward_given = :false',
          ExpressionAttributeValues: marshall({ ':true': true, ':false': false }),
        }));
      } catch (err) {
        const code = err && (err.name || err.__type || '');
        if (/ConditionalCheckFailedException/i.test(code)) {
          return send(res, 200, { data: { awarded: false, reason: 'already_awarded' } });
        }
        throw err;
      }

      const reward = await applyRewardToOwner(referral.ownerId, 'listing');

      const listerRow = await getUserRow(house.owner_id);
      await appendHistoryAndIncrement(referral.referralId, {
        userId: house.owner_id,
        name: (listerRow && listerRow.name) || '',
        email: (listerRow && listerRow.email) || '',
        type: 'listing',
        houseId,
        rewardType: reward.rewardType,
        rewardAmount: reward.rewardAmount,
        createdAt: new Date().toISOString(),
      }, 'listingReferrals');

      console.log(`[Referrals] Listing referral reward given: house=${houseId} referrer=${referral.ownerId}`);
      return send(res, 200, { data: { awarded: true, referrer_id: referral.ownerId, reward } });
    }

    return send(res, 400, { error: { message: `Unknown action "${action}"` } });
  } catch (err) {
    console.error('[Referrals] Request failed:', err && err.message);
    const status = /authoriz|token/i.test(err && err.message || '') ? 401 : 500;
    return send(res, status, { error: { message: (err && err.message) || 'Internal server error' } });
  }
};
