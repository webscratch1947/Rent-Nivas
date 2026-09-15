const crypto = require('crypto');
const { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, DeleteItemCommand, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION;
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const APP_CLIENT_ID = process.env.COGNITO_APP_CLIENT_ID;
const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;
const JWKS_URL = `${ISSUER}/.well-known/jwks.json`;
let jwksCache = null;
let jwksFetchedAt = 0;

function send(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(payload));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; });
    req.on('end', () => {
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch (err) { reject(err); }
    });
    req.on('error', reject);
  });
}

function b64url(input) {
  return Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

async function getJwks() {
  if (jwksCache && Date.now() - jwksFetchedAt < 60 * 60 * 1000) return jwksCache;
  const resp = await fetch(JWKS_URL);
  if (!resp.ok) throw new Error('Unable to load Cognito signing keys');
  jwksCache = await resp.json();
  jwksFetchedAt = Date.now();
  return jwksCache;
}

function jwkToPem(jwk) {
  const keyObject = crypto.createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: 'jwk' });
  return keyObject.export({ type: 'spki', format: 'pem' });
}

async function verifyToken(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) throw new Error('Missing authorization token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid authorization token');
  const header = JSON.parse(b64url(parts[0]).toString('utf8'));
  const payload = JSON.parse(b64url(parts[1]).toString('utf8'));
  if (payload.iss !== ISSUER) throw new Error('Invalid token issuer');
  if (payload.client_id !== APP_CLIENT_ID && payload.aud !== APP_CLIENT_ID) throw new Error('Invalid token audience');
  if (payload.exp * 1000 <= Date.now()) throw new Error('Authorization token expired');
  const jwks = await getJwks();
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid);
  if (!jwk) throw new Error('Unknown token signing key');
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(`${parts[0]}.${parts[1]}`);
  verifier.end();
  if (!verifier.verify(jwkToPem(jwk), b64url(parts[2]))) throw new Error('Invalid token signature');
  return payload;
}

function isAdmin(claims) {
  const groups = claims['cognito:groups'] || [];
  const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean);
  return groups.includes('admin') || groups.includes('Admin') || adminEmails.includes(String(claims.email || '').toLowerCase());
}

async function requireAdmin(req) {
  const claims = await verifyToken(req);
  if (!isAdmin(claims)) throw new Error('Admin access required');
  return claims;
}

// ═══════════════════════════════════════════════════════════════════════════
// SHARED DUPLICATE-ACCOUNT MERGE LOGIC
// ═══════════════════════════════════════════════════════════════════════════
// This lives here (in the shared _auth helper) rather than its own file on
// purpose: this project is already at Vercel's serverless function limit,
// and every file directly under /api — including underscore-prefixed
// "private" helpers like this one — counts as a function. _auth.js is
// already required by every route, so adding to it costs nothing, while a
// new api/_account-merge.js file would have pushed the count past the
// limit.
//
// Why this exists at all:
// Two separate, DIFFERENT merge implementations used to exist:
//   - api/auth.js's automatic merge (fires every time someone signs in with
//     Google) only ever copied over the Users profile row — credits, name,
//     referral_code. Nothing else.
//   - api/data.js's admin-only `admin_merge_duplicate_accounts` RPC moved
//     most app data (houses, purchases, favorites, unlocks, partner
//     applications, notifications, bans, warnings) but had never been
//     taught about the Broker Network tables (BrokerPosts/
//     BrokerConnections/BrokerProfiles), which live in a completely
//     separate AWS account/credentials from everything else.
// Both gaps produced the exact same symptom from the user's side: sign in
// again (especially via Google) and your broker posts / listings / other
// "stuff" appears to have vanished, because it's still sitting under the
// OLD account's id while the app is now looking at the NEW one.
//
// Fixing it once here — and having both call sites use this — means the
// two flows can't quietly drift apart again the way they did before.
const REGION_MERGE = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const mergeDdb = new DynamoDBClient({ region: REGION_MERGE });

// Broker Network tables use their own separate AWS credentials — see
// api/data.js's `brokerDdb` for the original definition this mirrors.
const MERGE_BROKER_REGION = process.env.BROKER_AWS_REGION || process.env.broker_aws_region || REGION_MERGE;
const mergeBrokerDdb = new DynamoDBClient({
  region: MERGE_BROKER_REGION,
  credentials: {
    accessKeyId: process.env.BROKER_AWS_KEY || process.env.broker_aws_key || '',
    secretAccessKey: process.env.BROKER_AWS_SECRET || process.env.broker_aws_secret || '',
  },
});

const MERGE_TABLE_USERS                = process.env.TABLE_USERS || 'Users';
const MERGE_TABLE_HOUSES               = process.env.TABLE_HOUSES || 'Properties';
const MERGE_TABLE_PURCHASES            = process.env.TABLE_PURCHASES || 'Purchases';
const MERGE_TABLE_FAVORITES            = process.env.TABLE_FAVORITES || 'Favorites';
const MERGE_TABLE_USER_HOUSE_UNLOCKS   = process.env.TABLE_USER_HOUSE_UNLOCKS || 'UserHouseUnlocks';
const MERGE_TABLE_PARTNER_APPLICATIONS = process.env.TABLE_PARTNER_APPLICATIONS || 'PartnerApplications';
const MERGE_TABLE_NOTIFICATIONS        = process.env.TABLE_NOTIFICATIONS || 'Notifications';
const MERGE_TABLE_ADMIN_BANS           = process.env.TABLE_ADMIN_BANS || 'Bans';
const MERGE_TABLE_ADMIN_WARNINGS       = process.env.TABLE_ADMIN_WARNINGS || 'Warnings';
const MERGE_TABLE_CONTACTS             = process.env.TABLE_CONTACTS || 'Contacts';
const MERGE_TABLE_PROPERTY_REPORTS     = process.env.TABLE_PROPERTY_REPORTS || 'PropertyReports';
const MERGE_TABLE_REFERRALS            = process.env.TABLE_REFERRALS || 'Referrals';
const MERGE_TABLE_BROKER_POSTS         = 'BrokerPosts';
const MERGE_TABLE_BROKER_CONNECTIONS   = 'BrokerConnections';
const MERGE_TABLE_BROKER_PROFILES      = 'BrokerProfiles';

// Plain-attribute ownership (userId/owner_id is NOT part of the table's
// primary key) — a straight UpdateItem per matching row is enough.
async function mergeRepointSimple(client, tableName, pkName, attr, loserId, keeperId) {
  let count = 0;
  try {
    const scanRes = await client.send(new ScanCommand({
      TableName: tableName,
      FilterExpression: `${attr} = :loser`,
      ExpressionAttributeValues: marshall({ ':loser': loserId }),
    }));
    const items = (scanRes.Items || []).map(unmarshall);
    for (const item of items) {
      await client.send(new UpdateItemCommand({
        TableName: tableName,
        Key: marshall({ [pkName]: item[pkName] }),
        UpdateExpression: `SET ${attr} = :keeper`,
        ExpressionAttributeValues: marshall({ ':keeper': keeperId }),
      }));
      count++;
    }
  } catch (err) {
    console.warn(`[AccountMerge] repoint ${tableName}.${attr} failed (non-fatal):`, err.message);
  }
  return count;
}

// Composite-key ownership (userId IS part of the table's primary key, e.g.
// Favorites is keyed by {userId, propertyId}) — the row has to be
// re-created under the keeper's id and the old one deleted, since you
// can't UpdateItem a partition key in place.
async function mergeRepointComposite(client, tableName, pk1, pk2, loserId, keeperId) {
  let count = 0;
  try {
    const scanRes = await client.send(new ScanCommand({
      TableName: tableName,
      FilterExpression: `${pk1} = :loser`,
      ExpressionAttributeValues: marshall({ ':loser': loserId }),
    }));
    const items = (scanRes.Items || []).map(unmarshall);
    for (const item of items) {
      const next = Object.assign({}, item, { [pk1]: keeperId });
      await client.send(new PutItemCommand({ TableName: tableName, Item: marshall(next, { removeUndefinedValues: true }) }));
      await client.send(new DeleteItemCommand({ TableName: tableName, Key: marshall({ [pk1]: loserId, [pk2]: item[pk2] }) })).catch(() => {});
      count++;
    }
  } catch (err) {
    console.warn(`[AccountMerge] repoint composite ${tableName} failed (non-fatal):`, err.message);
  }
  return count;
}

async function mergeRepointBrokerConnections(loserId, keeperId) {
  let count = 0;
  try {
    const scanRes = await mergeBrokerDdb.send(new ScanCommand({ TableName: MERGE_TABLE_BROKER_CONNECTIONS }));
    const items = (scanRes.Items || []).map(unmarshall);
    for (const item of items) {
      const patch = {};
      if (item.userId === loserId) patch.userId = keeperId;
      if (item.targetUserId === loserId) patch.targetUserId = keeperId;
      if (!Object.keys(patch).length) continue;
      const names = {};
      const values = {};
      const sets = Object.keys(patch).map((k, i) => {
        names[`#f${i}`] = k;
        values[`:v${i}`] = patch[k];
        return `#f${i} = :v${i}`;
      }).join(', ');
      await mergeBrokerDdb.send(new UpdateItemCommand({
        TableName: MERGE_TABLE_BROKER_CONNECTIONS,
        Key: marshall({ connectionId: item.connectionId }),
        UpdateExpression: 'SET ' + sets,
        ExpressionAttributeNames: names,
        ExpressionAttributeValues: marshall(values),
      }));
      count++;
    }
  } catch (err) {
    console.warn('[AccountMerge] repoint BrokerConnections failed (non-fatal):', err.message);
  }
  return count;
}

// BrokerProfiles' partition key IS userId itself, so this can't be a plain
// attribute update — merge the loser's row onto the keeper's (OR-ing the
// broker/verified/plan flags together so neither side's access is ever
// lost) and delete the loser's row, mirroring how the Users profile row
// itself is merged below.
async function mergeBrokerProfile(loserId, keeperId) {
  try {
    const [loserRes, keeperRes] = await Promise.all([
      mergeBrokerDdb.send(new GetItemCommand({ TableName: MERGE_TABLE_BROKER_PROFILES, Key: marshall({ userId: loserId }) })),
      mergeBrokerDdb.send(new GetItemCommand({ TableName: MERGE_TABLE_BROKER_PROFILES, Key: marshall({ userId: keeperId }) })),
    ]);
    const loserBp = loserRes.Item ? unmarshall(loserRes.Item) : null;
    const keeperBp = keeperRes.Item ? unmarshall(keeperRes.Item) : null;
    if (!loserBp) return 0;
    const merged = Object.assign({}, loserBp, keeperBp || {});
    merged.userId = keeperId;
    merged.isBroker = !!(loserBp.isBroker || (keeperBp && keeperBp.isBroker));
    merged.isVerified = !!(loserBp.isVerified || (keeperBp && keeperBp.isVerified));
    merged.hasBrokerPlan = !!(loserBp.hasBrokerPlan || (keeperBp && keeperBp.hasBrokerPlan));
    await mergeBrokerDdb.send(new PutItemCommand({ TableName: MERGE_TABLE_BROKER_PROFILES, Item: marshall(merged, { removeUndefinedValues: true }) }));
    await mergeBrokerDdb.send(new DeleteItemCommand({ TableName: MERGE_TABLE_BROKER_PROFILES, Key: marshall({ userId: loserId }) })).catch(() => {});
    return 1;
  } catch (err) {
    console.warn('[AccountMerge] merge BrokerProfiles failed (non-fatal):', err.message);
    return 0;
  }
}

// Moves every piece of data this app knows how to attribute to a user from
// loserUserId onto keeperUserId, then merges and removes the loser's Users
// profile row. Does NOT touch Cognito logins — callers handle that
// themselves (the two call sites have slightly different needs there:
// the automatic Google-merge always deletes the old login outright, the
// admin tool double-checks the email match first).
async function mergeDuplicateAccountData(loserUserId, keeperUserId) {
  if (!loserUserId || !keeperUserId || loserUserId === keeperUserId) {
    return { merged: false, reason: 'invalid-ids' };
  }

  const [loserRowRes, keeperRowRes] = await Promise.all([
    mergeDdb.send(new GetItemCommand({ TableName: MERGE_TABLE_USERS, Key: marshall({ userId: loserUserId }) })),
    mergeDdb.send(new GetItemCommand({ TableName: MERGE_TABLE_USERS, Key: marshall({ userId: keeperUserId }) })),
  ]);
  const loserRow = loserRowRes.Item ? unmarshall(loserRowRes.Item) : null;
  const keeperRow = keeperRowRes.Item ? unmarshall(keeperRowRes.Item) : null;
  if (!loserRow) return { merged: false, reason: 'no-loser-row' };

  const repointed = {};

  // Main-account tables — plain owner_id/user_id attribute.
  repointed.houses                = await mergeRepointSimple(mergeDdb, MERGE_TABLE_HOUSES, 'propertyId', 'owner_id', loserUserId, keeperUserId);
  repointed.purchases_user_id     = await mergeRepointSimple(mergeDdb, MERGE_TABLE_PURCHASES, 'purchaseId', 'user_id', loserUserId, keeperUserId);
  repointed.purchases_buyer_id    = await mergeRepointSimple(mergeDdb, MERGE_TABLE_PURCHASES, 'purchaseId', 'buyer_id', loserUserId, keeperUserId);
  repointed.partner_applications  = await mergeRepointSimple(mergeDdb, MERGE_TABLE_PARTNER_APPLICATIONS, 'applicationId', 'user_id', loserUserId, keeperUserId);
  repointed.bans                  = await mergeRepointSimple(mergeDdb, MERGE_TABLE_ADMIN_BANS, 'banId', 'user_id', loserUserId, keeperUserId);
  repointed.warnings              = await mergeRepointSimple(mergeDdb, MERGE_TABLE_ADMIN_WARNINGS, 'warningId', 'user_id', loserUserId, keeperUserId);
  repointed.contacts              = await mergeRepointSimple(mergeDdb, MERGE_TABLE_CONTACTS, 'contactId', 'user_id', loserUserId, keeperUserId);
  repointed.property_reports      = await mergeRepointSimple(mergeDdb, MERGE_TABLE_PROPERTY_REPORTS, 'id', 'user_id', loserUserId, keeperUserId);

  // Composite-key tables — userId is part of the row's primary key.
  repointed.favorites          = await mergeRepointComposite(mergeDdb, MERGE_TABLE_FAVORITES, 'userId', 'propertyId', loserUserId, keeperUserId);
  repointed.user_house_unlocks = await mergeRepointComposite(mergeDdb, MERGE_TABLE_USER_HOUSE_UNLOCKS, 'userId', 'propertyId', loserUserId, keeperUserId);
  repointed.notifications      = await mergeRepointComposite(mergeDdb, MERGE_TABLE_NOTIFICATIONS, 'userId', 'notificationId', loserUserId, keeperUserId);

  // Broker Network — separate AWS account. This category was the one the
  // old automatic merge never touched at all.
  repointed.broker_posts       = await mergeRepointSimple(mergeBrokerDdb, MERGE_TABLE_BROKER_POSTS, 'postId', 'userId', loserUserId, keeperUserId);
  repointed.broker_connections = await mergeRepointBrokerConnections(loserUserId, keeperUserId);
  repointed.broker_profiles    = await mergeBrokerProfile(loserUserId, keeperUserId);

  // Users profile row itself: sum credits/xp so no value is lost either
  // direction, keep whichever referral_code/name is actually set, then
  // write onto the keeper and remove the loser's row.
  const mergedCredits   = (parseFloat((keeperRow && keeperRow.credits)) || 0) + (parseFloat(loserRow.credits) || 0);
  const mergedXp        = (parseInt((keeperRow && keeperRow.xp), 10) || 0) + (parseInt(loserRow.xp, 10) || 0);
  const mergedPartnerXp = (parseInt((keeperRow && keeperRow.partner_xp), 10) || 0) + (parseInt(loserRow.partner_xp, 10) || 0);
  const merged = Object.assign({}, loserRow, keeperRow || {});
  merged.userId = keeperUserId;
  merged.credits = Math.round(mergedCredits * 100) / 100;
  merged.xp = mergedXp;
  merged.partner_xp = mergedPartnerXp;
  if (!merged.referral_code && loserRow.referral_code) merged.referral_code = loserRow.referral_code;
  if ((!merged.name || merged.name === 'User') && loserRow.name) merged.name = loserRow.name;
  merged.updated_at = new Date().toISOString();

  // If the surviving referral_code came from the loser, re-point the
  // Referrals record (keyed by the code itself) to the keeper's id so the
  // code keeps working for whoever already has it.
  if (merged.referral_code && (!keeperRow || keeperRow.referral_code !== merged.referral_code)) {
    try {
      await mergeDdb.send(new UpdateItemCommand({
        TableName: MERGE_TABLE_REFERRALS,
        Key: marshall({ referralId: merged.referral_code }),
        UpdateExpression: 'SET userId = :uid',
        ExpressionAttributeValues: marshall({ ':uid': keeperUserId }),
      }));
    } catch (e) {
      console.warn('[AccountMerge] could not re-point Referrals record:', e.message);
    }
  }

  await mergeDdb.send(new PutItemCommand({ TableName: MERGE_TABLE_USERS, Item: marshall(merged, { removeUndefinedValues: true }) }));
  await mergeDdb.send(new DeleteItemCommand({ TableName: MERGE_TABLE_USERS, Key: marshall({ userId: loserUserId }) })).catch(() => {});
  await mergeDdb.send(new DeleteItemCommand({ TableName: MERGE_TABLE_USERS, Key: marshall({ id: loserUserId }) })).catch(() => {}); // legacy-keyed row, if any

  console.log(`[AccountMerge] Merged ${loserUserId} -> ${keeperUserId}. Repointed:`, repointed);
  return { merged: true, repointed, profile: merged };
}

module.exports = { REGION, USER_POOL_ID, APP_CLIENT_ID, send, parseBody, verifyToken, requireAdmin, isAdmin, mergeDuplicateAccountData };
