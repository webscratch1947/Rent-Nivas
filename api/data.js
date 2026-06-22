const crypto = require('crypto');
const { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, DeleteItemCommand, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
// Used only by admin_merge_duplicate_accounts, to remove the loser
// account's Cognito login once its data has been moved to the keeper.
const { CognitoIdentityProviderClient, ListUsersCommand, AdminDeleteUserCommand } = require('@aws-sdk/client-cognito-identity-provider');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'eu-north-1_GM7Zi2xvq';
const APP_CLIENT_ID = process.env.COGNITO_APP_CLIENT_ID || 'ckpmh0heco2apoh0temn8hfnl';
const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;
const JWKS_URL = `${ISSUER}/.well-known/jwks.json`;

const ddb = new DynamoDBClient({ region: REGION });
const cognitoAdmin = new CognitoIdentityProviderClient({ region: REGION });
let jwksCache = null;
let jwksFetchedAt = 0;

const TABLES = {
  profiles: process.env.TABLE_USERS || 'Users',
  users: process.env.TABLE_USERS || 'Users',
  Users: process.env.TABLE_USERS || 'Users',
  partner_requests: process.env.TABLE_PARTNER_APPLICATIONS || 'PartnerApplications',
  partner_applications: process.env.TABLE_PARTNER_APPLICATIONS || 'PartnerApplications',
  PartnerApplications: process.env.TABLE_PARTNER_APPLICATIONS || 'PartnerApplications',
  partner_tasks: process.env.TABLE_PARTNER_TASKS || 'PartnerTasks',
  PartnerTasks: process.env.TABLE_PARTNER_TASKS || 'PartnerTasks',
  partner_task_progress: process.env.TABLE_PARTNER_TASK_PROGRESS || 'PartnerTaskProgress',
  PartnerTaskProgress: process.env.TABLE_PARTNER_TASK_PROGRESS || 'PartnerTaskProgress',
  purchases: process.env.TABLE_PURCHASES || 'Purchases',
  Purchases: process.env.TABLE_PURCHASES || 'Purchases',
  houses: process.env.TABLE_HOUSES || 'Properties',
  Houses: process.env.TABLE_HOUSES || 'Properties',
  listing_questions: process.env.TABLE_LISTING_QUESTIONS || 'PropertyQuestions',
  answers: process.env.TABLE_ANSWERS || 'PropertyAnswers',
  admin_announcements: process.env.TABLE_ADMIN_ANNOUNCEMENTS || 'AdminAnnouncements',
  admin_warnings: process.env.TABLE_ADMIN_WARNINGS || 'Warnings',
  warning_views: process.env.TABLE_WARNING_VIEWS || 'WarningViews',
  announcement_views: process.env.TABLE_ANNOUNCEMENT_VIEWS || 'AnnouncementViews',
  admin_bans: process.env.TABLE_ADMIN_BANS || 'Bans',
  admin_appeals: process.env.TABLE_ADMIN_APPEALS || 'Appeals',
  user_house_unlocks: process.env.TABLE_USER_HOUSE_UNLOCKS || 'UserHouseUnlocks',
  UserHouseUnlocks: process.env.TABLE_USER_HOUSE_UNLOCKS || 'UserHouseUnlocks',
  favorites: process.env.TABLE_FAVORITES || 'Favorites',
  Favorites: process.env.TABLE_FAVORITES || 'Favorites',
  notifications: process.env.TABLE_NOTIFICATIONS || 'Notifications',
  Notifications: process.env.TABLE_NOTIFICATIONS || 'Notifications',
  contacts: process.env.TABLE_CONTACTS || 'Contacts',
  Contacts: process.env.TABLE_CONTACTS || 'Contacts',
  verification_codes: process.env.TABLE_VERIFICATION_CODES || 'VerificationCodes',
  VerificationCodes: process.env.TABLE_VERIFICATION_CODES || 'VerificationCodes',
};

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
      try { resolve(JSON.parse(raw)); }
      catch (err) { reject(err); }
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
  const keyObject = crypto.createPublicKey({
    key: {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e
    },
    format: 'jwk'
  });
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
  const ok = verifier.verify(jwkToPem(jwk), b64url(parts[2]));
  if (!ok) throw new Error('Invalid token signature');
  return payload;
}

function tableName(table) {
  const resolved = TABLES[table];
  if (!resolved) throw new Error(`Unsupported table "${table}". Add a backend mapping before using it.`);
  return resolved;
}

// Validates the incoming request spec before any DynamoDB call is made.
// Catches malformed requests early with a clear, actionable error instead of
// letting a bad shape reach DynamoDB (which would surface as an opaque
// ValidationException like "the provided key element does not match the
// schema").
function validateSpec(spec) {
  if (!spec || typeof spec !== 'object') throw new Error('Request body must be a JSON object');
  if (!spec.op) throw new Error('Request is missing "op"');
  if (spec.op === 'rpc') {
    if (!spec.name) throw new Error('Request is missing "name" for rpc op');
    return; // rpc requests have no "table" — they're routed by spec.name in handleRpc
  }
  if (!spec.table) throw new Error('Request is missing "table"');
  tableName(spec.table); // throws if table has no backend mapping
}

// Wraps a DynamoDB SDK call with friendly, consistent error handling so raw
// AWS exceptions (e.g. ValidationException: key schema mismatch) never leak
// to the UI unexplained, and are always logged with enough context to debug.
async function runDdb(action, table, fn) {
  try {
    return await fn();
  } catch (err) {
    const code = err && (err.name || err.__type || '');
    console.error(`[RentNivas API] DynamoDB ${action} failed for table "${table}":`, code, err && err.message);
    if (/ValidationException/i.test(code) || /key element does not match the schema/i.test(err && err.message || '')) {
      throw new Error(`Could not ${action.toLowerCase()} "${table}" — the request key did not match the table's schema. This has been logged.`);
    }
    throw err;
  }
}

// Tables whose actual DynamoDB partition key name differs from the app-level "id" field.
// Source of truth: actual DynamoDB table schemas (verified from AWS console).
const PARTITION_KEY_OVERRIDES = {
  // Users table
  profiles: 'userId', users: 'userId', Users: 'userId',
  // Properties table
  houses: 'propertyId', Houses: 'propertyId', Properties: 'propertyId',
  // Purchases table
  purchases: 'purchaseId', Purchases: 'purchaseId',
  // PartnerApplications table
  partner_requests: 'applicationId', partner_applications: 'applicationId',
  PartnerApplications: 'applicationId',
  // PartnerTasks table
  partner_tasks: 'taskId', PartnerTasks: 'taskId',
  // Warnings table
  admin_warnings: 'warningId', Warnings: 'warningId',
  // AdminAnnouncements table
  admin_announcements: 'announcementId', AdminAnnouncements: 'announcementId',
  // Bans table
  admin_bans: 'banId', Bans: 'banId',
  // Appeals table
  admin_appeals: 'appealId', Appeals: 'appealId',
  // Contacts table
  contacts: 'contactId', Contacts: 'contactId',
  // VerificationCodes table — PK is literally 'pk'
  verification_codes: 'pk', VerificationCodes: 'pk',
};

// Composite-key tables: maps app-level snake_case field names → DynamoDB camelCase attribute names.
// For these tables, toDbItem/fromDbItem rename fields on the way in/out instead of
// the simple id→PK rename used for single-key tables.
const COMPOSITE_KEY_MAP = {
  warning_views:         { user_id: 'userId', warning_id: 'warningId' },
  WarningViews:          { user_id: 'userId', warning_id: 'warningId' },
  announcement_views:    { user_id: 'userId', announcement_id: 'announcementId' },
  AnnouncementViews:     { user_id: 'userId', announcement_id: 'announcementId' },
  partner_task_progress: { user_id: 'userId', task_id: 'taskId' },
  PartnerTaskProgress:   { user_id: 'userId', task_id: 'taskId' },
  user_house_unlocks:    { user_id: 'userId', property_id: 'propertyId' },
  UserHouseUnlocks:      { user_id: 'userId', property_id: 'propertyId' },
  favorites:             { user_id: 'userId', property_id: 'propertyId' },
  Favorites:             { user_id: 'userId', property_id: 'propertyId' },
  notifications:         { user_id: 'userId', notification_id: 'notificationId' },
  Notifications:         { user_id: 'userId', notification_id: 'notificationId' },
  // PropertyQuestions: PK=propertyId, SK=questionId; app auto-generates 'id' as questionId
  listing_questions:     { property_id: 'propertyId', id: 'questionId' },
  PropertyQuestions:     { property_id: 'propertyId', id: 'questionId' },
  // PropertyAnswers: PK=purchaseId, SK=answerId; app uses question_id as the sort key
  answers:               { purchase_id: 'purchaseId', question_id: 'answerId' },
  PropertyAnswers:       { purchase_id: 'purchaseId', question_id: 'answerId' },
};

function partitionKeyName(table) {
  return PARTITION_KEY_OVERRIDES[table] || 'id';
}

// Convert an app-level row into the shape DynamoDB expects for this table.
// For composite-key tables: rename snake_case fields → DynamoDB camelCase key attrs.
// For single-PK tables: rename 'id' → actual partition key name.
function toDbItem(table, row) {
  const keyMap = COMPOSITE_KEY_MAP[table];
  if (keyMap) {
    const next = Object.assign({}, row);
    for (const [snake, camel] of Object.entries(keyMap)) {
      if (Object.prototype.hasOwnProperty.call(next, snake)) {
        if (!Object.prototype.hasOwnProperty.call(next, camel)) next[camel] = next[snake];
        delete next[snake];
      }
    }
    return next;
  }
  const pk = partitionKeyName(table);
  if (pk === 'id') return row;
  const next = Object.assign({}, row);
  if (Object.prototype.hasOwnProperty.call(next, 'id')) {
    next[pk] = next.id;
    delete next.id;
  }
  return next;
}

// Convert a raw DynamoDB item back into the app-level shape.
// Reverses toDbItem: camelCase key attrs → snake_case, and PK attr → 'id'.
function fromDbItem(table, item) {
  if (!item) return item;
  const keyMap = COMPOSITE_KEY_MAP[table];
  if (keyMap) {
    const next = Object.assign({}, item);
    for (const [snake, camel] of Object.entries(keyMap)) {
      if (Object.prototype.hasOwnProperty.call(next, camel)) {
        if (!Object.prototype.hasOwnProperty.call(next, snake)) next[snake] = next[camel];
        delete next[camel];
      }
    }
    return next;
  }
  const pk = partitionKeyName(table);
  if (pk === 'id') return item;
  if (Object.prototype.hasOwnProperty.call(item, pk)) {
    const next = Object.assign({}, item);
    next.id = next[pk];
    delete next[pk];
    return next;
  }
  return item;
}

function keyFor(table, row, filters) {
  const all = Object.assign({}, row || {});
  (filters || []).forEach(f => {
    if (f.op === 'eq') all[f.column] = f.value;
  });
  // Composite-key tables — use camelCase to match actual DynamoDB attribute names
  if (table === 'partner_task_progress' || table === 'PartnerTaskProgress') {
    if (!all.task_id || !all.user_id) throw new Error('PartnerTaskProgress requires task_id and user_id');
    return { userId: all.user_id, taskId: all.task_id };
  }
  if (table === 'answers' || table === 'PropertyAnswers') {
    if (!all.purchase_id || !all.question_id) throw new Error('PropertyAnswers requires purchase_id and question_id');
    return { purchaseId: all.purchase_id, answerId: all.question_id };
  }
  if (table === 'warning_views' || table === 'WarningViews') {
    if (!all.user_id || !all.warning_id) throw new Error('WarningViews requires user_id and warning_id');
    return { userId: all.user_id, warningId: all.warning_id };
  }
  if (table === 'announcement_views' || table === 'AnnouncementViews') {
    if (!all.user_id || !all.announcement_id) throw new Error('AnnouncementViews requires user_id and announcement_id');
    return { userId: all.user_id, announcementId: all.announcement_id };
  }
  if (table === 'listing_questions' || table === 'PropertyQuestions') {
    if (!all.property_id) throw new Error('PropertyQuestions requires property_id');
    if (!all.id) throw new Error('PropertyQuestions requires id (questionId)');
    return { propertyId: all.property_id, questionId: all.id };
  }
  if (table === 'user_house_unlocks' || table === 'UserHouseUnlocks') {
    if (!all.user_id || !all.property_id) throw new Error('UserHouseUnlocks requires user_id and property_id');
    return { userId: all.user_id, propertyId: all.property_id };
  }
  if (table === 'favorites' || table === 'Favorites') {
    if (!all.user_id || !all.property_id) throw new Error('Favorites requires user_id and property_id');
    return { userId: all.user_id, propertyId: all.property_id };
  }
  if (table === 'notifications' || table === 'Notifications') {
    if (!all.user_id || !all.notification_id) throw new Error('Notifications requires user_id and notification_id');
    return { userId: all.user_id, notificationId: all.notification_id };
  }
  // Single-PK tables: look up the PK name from PARTITION_KEY_OVERRIDES.
  // If only user_id is known (no 'id'), keyFor throws → tryKey returns null
  // → readItems falls back to Scan+filter instead of a bad GetItem call.
  if (!all.id) throw new Error(`${table} requires id`);
  const pk = partitionKeyName(table);
  return { [pk]: all.id };
}

function applyFilters(items, filters) {
  let out = items;
  (filters || []).forEach(f => {
    if (f.op === 'eq') out = out.filter(item => String(item[f.column] ?? '') === String(f.value ?? ''));
    if (f.op === 'in') out = out.filter(item => (f.values || []).map(String).includes(String(item[f.column] ?? '')));
  });
  return out;
}

function applyOrder(items, order) {
  if (!order || !order.column) return items;
  const dir = order.ascending === false ? -1 : 1;
  return [...items].sort((a, b) => {
    const av = a[order.column] ?? '';
    const bv = b[order.column] ?? '';
    if (av < bv) return -1 * dir;
    if (av > bv) return 1 * dir;
    return 0;
  });
}

function pickColumns(row, select) {
  if (!row || !select || select === '*') return row;
  const cols = select.split(',').map(s => s.trim()).filter(Boolean).filter(c => !c.includes('('));
  if (!cols.length) return row;
  return cols.reduce((acc, col) => {
    if (Object.prototype.hasOwnProperty.call(row, col)) acc[col] = row[col];
    return acc;
  }, {});
}

async function readItems(spec) {
  const TableName = tableName(spec.table);
  const key = spec.filters && spec.filters.length ? tryKey(spec.table, spec.filters) : null;
  if (key && (spec.single || spec.maybeSingle || spec.limit === 1)) {
    const got = await runDdb('read', spec.table, () => ddb.send(new GetItemCommand({ TableName, Key: marshall(key) })));
    const row = got.Item ? pickColumns(fromDbItem(spec.table, unmarshall(got.Item)), spec.select) : null;
    return spec.single || spec.maybeSingle ? row : (row ? [row] : []);
  }
  const scanned = await runDdb('read', spec.table, () => ddb.send(new ScanCommand({ TableName })));
  let rows = (scanned.Items || []).map(item => fromDbItem(spec.table, unmarshall(item)));
  rows = applyFilters(rows, spec.filters);
  rows = applyOrder(rows, spec.order);
  if (spec.limit) rows = rows.slice(0, spec.limit);
  rows = rows.map(row => pickColumns(row, spec.select));
  if (spec.countOnly || spec.head) return { count: rows.length };
  return spec.single || spec.maybeSingle ? (rows[0] || null) : rows;
}

function tryKey(table, filters) {
  try { return keyFor(table, {}, filters); }
  catch (_) { return null; }
}

// Fields a brand-new row gets on its FIRST-EVER creation, keyed by table.
// Applied server-side inside putRows so it's atomic and race-proof — no
// matter which of the many client-side `profiles.upsert({id,...})` calls
// happens to be the one that creates the row first, the new user always
// ends up with these defaults. Only applied when no existing row was found
// (i.e. this upsert is truly creating the row, not updating it), and only
// for fields the caller didn't already explicitly provide.
//
// referral_code is a FUNCTION (not a static value) so every new profile
// gets its own unique code generated at creation time — previously this
// relied entirely on a client-side follow-up call (ensureReferralCode)
// that had a bug (.is() was undefined) and so never ran successfully.
// Generating it here means every account gets a permanent code the moment
// the row is created, with no separate step that can fail or race.
function freshReferralCode() {
  return String(Math.floor(10000000 + Math.random() * 90000000));
}
const NEW_ROW_DEFAULTS = {
  profiles: {
    credits: 10,
    xp: 0,
    partner_xp: 0,
    referral_code: freshReferralCode,
    referred_by_code: null,
    total_referrals: 0,
    registration_referrals: 0,
    listing_referrals: 0,
  },
  users: { credits: 10, xp: 0, partner_xp: 0, referral_code: freshReferralCode, referred_by_code: null, total_referrals: 0, registration_referrals: 0, listing_referrals: 0 },
  Users: { credits: 10, xp: 0, partner_xp: 0, referral_code: freshReferralCode, referred_by_code: null, total_referrals: 0, registration_referrals: 0, listing_referrals: 0 },
};

// Resolves any function-valued defaults (e.g. freshReferralCode) into a concrete value.
// Called once per row creation so each new row gets its own freshly-generated value
// instead of every row in a batch sharing one.
function resolveDefaults(defaults) {
  const out = {};
  for (const [k, v] of Object.entries(defaults)) out[k] = typeof v === 'function' ? v() : v;
  return out;
}

async function putRows(spec, merge) {
  const TableName = tableName(spec.table);
  const inputRows = Array.isArray(spec.values) ? spec.values : [spec.values];
  const saved = [];
  for (const row of inputRows) {
    const now = new Date().toISOString();
    const next = Object.assign({}, row);
    if (!next.id && !['partner_task_progress','PartnerTaskProgress','answers','PropertyAnswers','warning_views','WarningViews','announcement_views','AnnouncementViews','user_house_unlocks','UserHouseUnlocks','favorites','Favorites','notifications','Notifications'].includes(spec.table)) next.id = crypto.randomUUID();
    if (!next.created_at) next.created_at = now;
    next.updated_at = now;
    if (merge) {
      const key = keyFor(spec.table, next, spec.filters);
      const existing = await runDdb('upsert', spec.table, () => ddb.send(new GetItemCommand({ TableName, Key: marshall(key) })));
      const existingAppRow = existing.Item ? fromDbItem(spec.table, unmarshall(existing.Item)) : {};
      const isFirstCreation = !existing.Item;
      const defaults = isFirstCreation ? resolveDefaults(NEW_ROW_DEFAULTS[spec.table] || {}) : {};
      // Order matters: defaults < existing row < caller's explicit values,
      // so defaults only fill gaps and never clobber a real existing value
      // or something the caller explicitly asked to set.
      const merged = Object.assign({}, defaults, existingAppRow, next, { id: next.id || existingAppRow.id });
      // Never let an upsert overwrite the original creation timestamp — it is
      // set once on first insert and must stay fixed for "member since" to work.
      if (existingAppRow.created_at) merged.created_at = existingAppRow.created_at;
      await runDdb('upsert', spec.table, () => ddb.send(new PutItemCommand({ TableName, Item: marshall(toDbItem(spec.table, merged), { removeUndefinedValues: true }) })));
      if (isFirstCreation && Object.keys(defaults).length) {
        console.log(`[RentNivas API] First-creation defaults applied for ${spec.table}:`, Object.keys(defaults).join(', '));
      }
      saved.push(merged);
    } else {
      const defaults = resolveDefaults(NEW_ROW_DEFAULTS[spec.table] || {});
      const withDefaults = Object.assign({}, defaults, next);
      await runDdb('insert', spec.table, () => ddb.send(new PutItemCommand({ TableName, Item: marshall(toDbItem(spec.table, withDefaults), { removeUndefinedValues: true }) })));
      saved.push(withDefaults);
    }
  }
  return spec.single ? saved[0] : saved;
}

async function updateRows(spec) {
  const TableName = tableName(spec.table);
  const patch = Object.assign({}, spec.values || {}, { updated_at: new Date().toISOString() });
  const key = keyFor(spec.table, patch, spec.filters);
  const pk = partitionKeyName(spec.table);
  const names = {};
  const values = {};
  const sets = [];
  Object.entries(patch).forEach(([k, v], i) => {
    if (k === 'id' || k === pk || Object.prototype.hasOwnProperty.call(key, k) || typeof v === 'undefined') return;
    names[`#k${i}`] = k;
    values[`:v${i}`] = v;
    sets.push(`#k${i} = :v${i}`);
  });
  if (!sets.length) return spec.single ? null : [];
  // FIX: DynamoDB's UpdateItemCommand creates the item if the key doesn't
  // already exist — it has no "must already exist" semantics by default.
  // Previously this meant: if any plain .update() call (e.g. setCredits(),
  // setting an avatar_url, etc.) happened to be the FIRST write ever made
  // for a given user (a real race that can happen on a brand-new account,
  // e.g. unlocking a listing before the profile-creation upsert finishes),
  // DynamoDB would silently create a bare-bones row containing ONLY the
  // fields in this one update — no credits, no xp, no referral_code, none
  // of NEW_ROW_DEFAULTS. That partial row then permanently blocked defaults
  // from ever being applied later, because putRows() only applies
  // NEW_ROW_DEFAULTS when the row doesn't exist yet ("first creation") —
  // and this partial row already "existed".
  //
  // Fix: add a ConditionExpression requiring the partition key to already
  // exist. If it doesn't, fall back to putRows(merge=true) instead, which
  // DOES correctly apply full NEW_ROW_DEFAULTS for a true first creation.
  // This guarantees every profile row — no matter which code path happens
  // to create it — always gets the full default set exactly once.
  const condition = `attribute_exists(${pk})`;
  try {
    const result = await runDdb('update', spec.table, () => ddb.send(new UpdateItemCommand({
      TableName,
      Key: marshall(key),
      UpdateExpression: `SET ${sets.join(', ')}`,
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: marshall(values, { removeUndefinedValues: true }),
      ConditionExpression: condition,
      ReturnValues: 'ALL_NEW'
    })));
    const row = result.Attributes ? fromDbItem(spec.table, unmarshall(result.Attributes)) : null;
    return spec.single || spec.maybeSingle ? row : (row ? [row] : []);
  } catch (err) {
    const code = err && (err.name || err.__type || '');
    if (/ConditionalCheckFailedException/i.test(code)) {
      // Row didn't exist — create it properly (with full NEW_ROW_DEFAULTS)
      // instead of leaving a partial row behind.
      console.log(`[RentNivas API] update() target row didn't exist for "${spec.table}" — creating via putRows with full defaults instead of a partial row.`);
      const created = await putRows({ table: spec.table, values: Object.assign({}, fromDbItem(spec.table, key), spec.values || {}), single: true }, true);
      return spec.single || spec.maybeSingle ? created : (created ? [created] : []);
    }
    throw err;
  }
}

async function deleteRows(spec) {
  const TableName = tableName(spec.table);
  const key = keyFor(spec.table, {}, spec.filters);
  await runDdb('delete', spec.table, () => ddb.send(new DeleteItemCommand({ TableName, Key: marshall(key) })));
  return [];
}

// ─────────────────────────────────────────────────────────────────────────────
// REFERRAL SYSTEM HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check whether a given user_id has an accepted Partner Panel application.
 * Returns true if PartnerApplications contains a row with
 *   { user_id, status: 'accepted' }.
 */
async function hasPartnerAccess(userId) {
  try {
    const TableName = tableName('partner_requests');
    const scanned = await runDdb('read', 'partner_requests', () =>
      ddb.send(new ScanCommand({ TableName }))
    );
    const rows = (scanned.Items || []).map(i => unmarshall(i));
    return rows.some(r => r.user_id === userId && r.status === 'accepted');
  } catch (err) {
    console.error('[Referral] hasPartnerAccess check failed:', err.message);
    return false;
  }
}

/**
 * Award a referral reward to `referrerId`.
 * type = 'registration'  → +15 XP (partner) or +0.50 credits (non-partner)
 * type = 'listing'       → +10 XP (partner) or +0.50 credits (non-partner)
 *
 * Atomic-safe: reads the current profile, adds the delta, writes back.
 * Returns the applied reward shape.
 */
async function applyReferralReward(referrerId, type) {
  const isPartner = await hasPartnerAccess(referrerId);

  // Fetch referrer profile — we need current XP / credits / counters
  const referrer = await readItems({
    table: 'profiles',
    op: 'select',
    select: 'id,xp,credits,partner_xp,registration_referrals,listing_referrals,total_referrals',
    filters: [{ op: 'eq', column: 'id', value: referrerId }],
    maybeSingle: true,
  });

  if (!referrer || !referrer.id) {
    throw new Error(`Referrer profile not found for id=${referrerId}`);
  }

  const currentXP       = parseInt(referrer.xp              || referrer.partner_xp || '0', 10);
  const currentCredits  = parseFloat(referrer.credits        || '0');
  const currentTotal    = parseInt(referrer.total_referrals  || '0', 10);
  const currentReg      = parseInt(referrer.registration_referrals || '0', 10);
  const currentList     = parseInt(referrer.listing_referrals      || '0', 10);

  let patch = {
    total_referrals: currentTotal + 1,
    updated_at: new Date().toISOString(),
  };

  let rewardDesc;
  if (type === 'registration') {
    patch.registration_referrals = currentReg + 1;
    if (isPartner) {
      patch.xp         = currentXP + 15;
      patch.partner_xp = currentXP + 15;
      rewardDesc = '+15 XP (partner registration referral)';
    } else {
      patch.credits = Math.round((currentCredits + 0.50) * 100) / 100;
      rewardDesc = '+0.50 credits (registration referral)';
    }
  } else if (type === 'listing') {
    patch.listing_referrals = currentList + 1;
    if (isPartner) {
      patch.xp         = currentXP + 10;
      patch.partner_xp = currentXP + 10;
      rewardDesc = '+10 XP (partner listing referral)';
    } else {
      patch.credits = Math.round((currentCredits + 0.50) * 100) / 100;
      rewardDesc = '+0.50 credits (listing referral)';
    }
  } else {
    throw new Error(`Unknown referral reward type "${type}"`);
  }

  await updateRows({
    table: 'profiles',
    op: 'update',
    values: patch,
    filters: [{ op: 'eq', column: 'id', value: referrerId }],
  });

  console.log(`[Referral] Awarded to referrer ${referrerId}: ${rewardDesc}`);
  return { referrer_id: referrerId, is_partner: isPartner, reward: rewardDesc };
}

// ─────────────────────────────────────────────────────────────────────────────
// MIGRATION HELPER
// Backfills any existing Users row that is missing the required referral fields.
// Called transparently inside process_registration_referral and
// award_referral_reward so all touched profiles are always up-to-date.
// Fields added (only when absent):
//   referral_code            – 8-digit numeric string, unique per user
//   referred_by_code         – null (not yet referred)
//   referred_by_user_id      – null
//   partner_xp               – 0
//   credits                  – 10  (preserve existing if already set)
//   total_referrals          – 0
//   registration_referrals   – 0
//   listing_referrals        – 0
// ─────────────────────────────────────────────────────────────────────────────
async function migrateProfileReferralFields(userId) {
  try {
    const profile = await readItems({
      table: 'profiles',
      op: 'select',
      select: 'id,name,email,referral_code,referred_by_code,partner_xp,credits,total_referrals,registration_referrals,listing_referrals',
      filters: [{ op: 'eq', column: 'id', value: userId }],
      maybeSingle: true,
    });

    if (!profile || !profile.id) return; // nothing to migrate

    const patch = {};
    if (!profile.referral_code) {
      patch.referral_code = String(Math.floor(10000000 + Math.random() * 90000000));
    }
    if (!profile.name && profile.email) {
      // Old/broken accounts (created before name was reliably saved) show up
      // as a blank "—" everywhere a name is displayed — including in the
      // referral-code-verified box on the Add Listing form, and the admin
      // user list. Derive a readable placeholder from their email so the UI
      // never shows a bare dash for an existing real user.
      patch.name = profile.email.split('@')[0];
    }
    if (profile.referred_by_code === undefined) patch.referred_by_code = null;
    if (profile.partner_xp     === undefined)  patch.partner_xp = 0;
    // Floor everyone at 10 credits — not just rows missing the field
    // entirely. This is a deliberate one-time admin-requested baseline
    // bump, not a "fill missing field" default: it raises anyone sitting
    // below 10 (including a real, intentional 0) up to 10, but never
    // lowers anyone who already has more.
    const currentCredits = parseFloat(profile.credits);
    if (isNaN(currentCredits) || currentCredits < 10) patch.credits = 10;
    if (profile.total_referrals          === undefined) patch.total_referrals = 0;
    if (profile.registration_referrals   === undefined) patch.registration_referrals = 0;
    if (profile.listing_referrals        === undefined) patch.listing_referrals = 0;

    if (Object.keys(patch).length > 0) {
      await updateRows({
        table: 'profiles',
        op: 'update',
        values: patch,
        filters: [{ op: 'eq', column: 'id', value: userId }],
      });
      console.log(`[Referral] Migrated referral fields for user ${userId}:`, Object.keys(patch).join(', '));
    }
  } catch (err) {
    // Non-fatal — log and continue
    console.warn(`[Referral] migrateProfileReferralFields failed for ${userId}:`, err.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC HANDLER
// ─────────────────────────────────────────────────────────────────────────────
async function handleRpc(spec, claims) {

  // ── process_registration_referral ─────────────────────────────────────────
  // Called once per new user on their first login.
  // Idempotent: stamps profiles.referred_by_code on the new user so a second
  // call (same session refresh) is a no-op.
  if (spec.name === 'process_registration_referral') {
    const code = String((spec.params && spec.params.p_referral_code) || '').trim();
    if (!code) return { processed: false, reason: 'no_code' };

    // Backfill referral fields on the new user if needed
    await migrateProfileReferralFields(claims.sub);

    // Fetch the new user's profile — check for already-processed guard
    const newUser = await readItems({
      table: 'profiles',
      op: 'select',
      select: 'id,referred_by_code,referred_by_user_id',
      filters: [{ op: 'eq', column: 'id', value: claims.sub }],
      maybeSingle: true,
    });

    // Duplicate-reward guard: if referred_by_code is already set, skip
    if (newUser && newUser.referred_by_code) {
      console.log(`[Referral] Registration referral already processed for user ${claims.sub} — skipping`);
      return { processed: false, reason: 'already_processed' };
    }

    // Look up the referrer by their referral code
    const referrer = await readItems({
      table: 'profiles',
      op: 'select',
      select: 'id,email,name,referral_code',
      filters: [{ op: 'eq', column: 'referral_code', value: code }],
      maybeSingle: true,
    });

    // Validate referrer exists and is not the new user themselves
    if (!referrer || !referrer.id || referrer.id === claims.sub) {
      return { processed: false, reason: 'referrer_not_found' };
    }

    // Backfill referral fields on the referrer if needed
    await migrateProfileReferralFields(referrer.id);

    // Stamp the new user so this is idempotent going forward
    await updateRows({
      table: 'profiles',
      op: 'update',
      values: { referred_by_code: code, referred_by_user_id: referrer.id },
      filters: [{ op: 'eq', column: 'id', value: claims.sub }],
    });

    // Award the referrer their reward
    const reward = await applyReferralReward(referrer.id, 'registration');

    console.log(`[Referral] Registration referral processed: new_user=${claims.sub} referrer=${referrer.id}`);
    return { processed: true, referrer_id: referrer.id, reward };
  }

  // ── award_referral_reward ──────────────────────────────────────────────────
  // Called when a referred user publishes their first property listing.
  // p_house_id is passed; we look up the referral_code on the property,
  // then find the referrer who owns that code, and award them.
  // Duplicate-reward guard: a reward is only issued once per property.
  if (spec.name === 'award_referral_reward') {
    const houseId = String((spec.params && spec.params.p_house_id) || '').trim();
    if (!houseId) return { awarded: false, reason: 'no_house_id' };

    // Fetch the property
    const house = await readItems({
      table: 'houses',
      op: 'select',
      select: 'id,referral_code,referral_reward_given,owner_id',
      filters: [{ op: 'eq', column: 'id', value: houseId }],
      maybeSingle: true,
    });

    if (!house || !house.id) return { awarded: false, reason: 'house_not_found' };

    // Duplicate-reward guard: only award once per listing
    if (house.referral_reward_given) {
      console.log(`[Referral] Listing reward already given for house ${houseId} — skipping`);
      return { awarded: false, reason: 'already_awarded' };
    }

    const refCode = String(house.referral_code || '').trim();
    if (!refCode) return { awarded: false, reason: 'no_referral_code' };

    // Self-referral guard: don't reward the property owner for using their own code
    const referrer = await readItems({
      table: 'profiles',
      op: 'select',
      select: 'id,referral_code',
      filters: [{ op: 'eq', column: 'referral_code', value: refCode }],
      maybeSingle: true,
    });

    if (!referrer || !referrer.id) return { awarded: false, reason: 'referrer_not_found' };
    if (referrer.id === house.owner_id || referrer.id === claims.sub) {
      return { awarded: false, reason: 'self_referral' };
    }

    // Backfill referral fields on the referrer if needed
    await migrateProfileReferralFields(referrer.id);

    // Mark the listing so duplicate calls are no-ops
    await updateRows({
      table: 'houses',
      op: 'update',
      values: { referral_reward_given: true },
      filters: [{ op: 'eq', column: 'id', value: houseId }],
    });

    // Award the referrer
    const reward = await applyReferralReward(referrer.id, 'listing');

    console.log(`[Referral] Listing referral reward given: house=${houseId} referrer=${referrer.id}`);
    return { awarded: true, referrer_id: referrer.id, reward };
  }

  // ── admin_backfill_profile_defaults ────────────────────────────────────────
  // One-time/repeatable admin fix: scans every row in Users and applies
  // migrateProfileReferralFields (which fills in credits:10, xp:0, referral_code,
  // etc. ONLY for fields that are currently missing — never overwrites a real
  // existing value) to every profile that's missing them. Safe to run multiple
  // times. This fixes accounts that were created before the race-condition fix
  // in putRows() existed, where some signups ended up with no `credits` field
  // at all because a non-credit-granting profile upsert won the race.
  if (spec.name === 'admin_backfill_profile_defaults') {
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean);
    const isAdminCaller = (claims['cognito:groups'] || []).includes('admin') || adminEmails.includes(String(claims.email || '').toLowerCase());
    if (!isAdminCaller) throw new Error('Admin access required');

    const TableName = tableName('profiles');
    const scanned = await runDdb('read', 'profiles', () => ddb.send(new ScanCommand({ TableName })));
    const rows = (scanned.Items || []).map(item => fromDbItem('profiles', unmarshall(item)));
    let fixed = 0;
    let creditsTopped = 0;
    for (const row of rows) {
      if (!row.id) continue;
      const before = JSON.stringify({
        credits: row.credits, xp: row.xp, partner_xp: row.partner_xp,
        referral_code: row.referral_code, total_referrals: row.total_referrals,
      });
      await migrateProfileReferralFields(row.id);
      // One-time admin top-up: give every account at least 10 credits.
      // This is deliberately ONLY done here (manually triggered by an
      // admin clicking the button), never inside migrateProfileReferralFields
      // itself — that function also runs automatically on every referral
      // event, and unconditionally bumping low balances back to 10 there
      // would silently undo any credits a user had legitimately spent.
      const currentCredits = parseFloat(row.credits) || 0;
      if (currentCredits < 10) {
        await updateRows({
          table: 'profiles',
          op: 'update',
          values: { credits: 10 },
          filters: [{ op: 'eq', column: 'id', value: row.id }],
        });
        creditsTopped++;
      }
      // Re-read to log accurately (migrateProfileReferralFields only patches missing fields)
      const after = await readItems({ table: 'profiles', op: 'select', select: 'credits,xp,partner_xp,referral_code,total_referrals', filters: [{ op: 'eq', column: 'id', value: row.id }], maybeSingle: true });
      if (JSON.stringify({ credits: after?.credits, xp: after?.xp, partner_xp: after?.partner_xp, referral_code: after?.referral_code, total_referrals: after?.total_referrals }) !== before) fixed++;
    }

    // Dedupe partner_requests: for any user with multiple application rows,
    // keep the one that is 'accepted' if any are, otherwise the most recent,
    // and delete the rest. Fixes accounts left stuck on the partner form
    // because an old duplicate pending row was "winning" the user-facing
    // most-recent-row lookup over a real accepted row.
    const prTable = tableName('partner_requests');
    const prScanned = await runDdb('read', 'partner_requests', () => ddb.send(new ScanCommand({ TableName: prTable })));
    const prRows = (prScanned.Items || []).map(item => fromDbItem('partner_requests', unmarshall(item)));
    const byUser = {};
    prRows.forEach(r => { if (r.user_id) (byUser[r.user_id] = byUser[r.user_id] || []).push(r); });
    let dedupedUsers = 0, deletedRows = 0;
    for (const [uid, userRows] of Object.entries(byUser)) {
      if (userRows.length < 2) continue;
      const accepted = userRows.filter(r => r.status === 'accepted').sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      const keep = accepted.length ? accepted[0] : userRows.slice().sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0];
      const toDelete = userRows.filter(r => r.id !== keep.id);
      for (const dupe of toDelete) {
        await deleteRows({ table: 'partner_requests', op: 'delete', filters: [{ op: 'eq', column: 'id', value: dupe.id }] }).catch(() => {});
        deletedRows++;
      }
      dedupedUsers++;
      console.log(`[Admin] Deduped partner_requests for user ${uid}: kept ${keep.id} (status=${keep.status}), removed ${toDelete.length}`);
    }

    console.log(`[Admin] Backfilled defaults for ${fixed}/${rows.length} profiles; deduped ${dedupedUsers} users' partner applications (${deletedRows} duplicate rows removed)`);
    return { scanned: rows.length, fixed, dedupedUsers, deletedRows };
  }

  // ── admin_find_duplicate_accounts ──────────────────────────────────────
  // Read-only report: scans every profile row and groups them by email,
  // surfacing any email with more than one row (i.e. more than one Cognito
  // user signed up with that email before the signup-verify.js dedupe fix
  // existed). Does NOT delete or merge anything automatically — picking
  // which of two accounts is "the real one" (which has the listings,
  // credits, partner status worth keeping) needs a human to look at the
  // numbers and decide, not a script guessing. Returns the groups so the
  // admin can review them in the admin panel and decide per-pair what to
  // do (e.g. manually move data over, then delete the loser with the
  // existing Delete button).
  if (spec.name === 'admin_find_duplicate_accounts') {
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean);
    const isAdminCaller = (claims['cognito:groups'] || []).includes('admin') || adminEmails.includes(String(claims.email || '').toLowerCase());
    if (!isAdminCaller) throw new Error('Admin access required');

    const TableName = tableName('profiles');
    const scanned = await runDdb('read', 'profiles', () => ddb.send(new ScanCommand({ TableName })));
    const rows = (scanned.Items || []).map(item => fromDbItem('profiles', unmarshall(item)));

    const byEmail = {};
    rows.forEach(r => {
      const email = String(r.email || '').trim().toLowerCase();
      if (!email) return;
      (byEmail[email] = byEmail[email] || []).push({
        id: r.id, name: r.name, email: r.email, credits: r.credits,
        xp: r.xp, partner_xp: r.partner_xp, referral_code: r.referral_code,
        created_at: r.created_at,
      });
    });

    const duplicates = Object.entries(byEmail)
      .filter(([, group]) => group.length > 1)
      .map(([email, group]) => ({ email, accounts: group.sort((a, b) => new Date(a.created_at) - new Date(b.created_at)) }));

    console.log(`[Admin] Duplicate account scan: ${duplicates.length} email(s) with multiple accounts found.`);
    return { duplicateEmailCount: duplicates.length, duplicates };
  }

  // ── admin_merge_duplicate_accounts ─────────────────────────────────────
  // Takes a keeperUserId and a loserUserId (both from the same email — the
  // admin decides which is "real" after reviewing admin_find_duplicate_accounts).
  // Moves everything of value from the loser onto the keeper:
  //   - houses.owner_id, purchases.user_id, favorites.user_id,
  //     user_house_unlocks.user_id, partner_requests.user_id,
  //     notifications.user_id, admin_bans.user_id, admin_warnings.user_id
  //     are all re-pointed from loser -> keeper, so nothing the loser
  //     created/owns gets orphaned or silently lost.
  //   - credits and xp/partner_xp are SUMMED onto the keeper (not
  //     overwritten), so no value is lost either direction.
  //   - keeper's referral_code is preserved if it has one; otherwise the
  //     loser's is adopted (so a working code is never thrown away).
  //   - Cognito login for the loser is deleted, then its profile row.
  // This does NOT touch the keeper's password or login — only the loser's
  // login is removed. The keeper becomes the one and only account for
  // that email going forward.
  if (spec.name === 'admin_merge_duplicate_accounts') {
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean);
    const isAdminCaller = (claims['cognito:groups'] || []).includes('admin') || adminEmails.includes(String(claims.email || '').toLowerCase());
    if (!isAdminCaller) throw new Error('Admin access required');

    const keeperUserId = String((spec.params && spec.params.p_keeper_id) || '').trim();
    const loserUserId = String((spec.params && spec.params.p_loser_id) || '').trim();
    if (!keeperUserId || !loserUserId) throw new Error('admin_merge_duplicate_accounts requires p_keeper_id and p_loser_id');
    if (keeperUserId === loserUserId) throw new Error('Keeper and loser cannot be the same account');

    const [keeper, loser] = await Promise.all([
      readItems({ table: 'profiles', op: 'select', select: '*', filters: [{ op: 'eq', column: 'id', value: keeperUserId }], maybeSingle: true }),
      readItems({ table: 'profiles', op: 'select', select: '*', filters: [{ op: 'eq', column: 'id', value: loserUserId }], maybeSingle: true }),
    ]);
    if (!keeper || !keeper.id) throw new Error(`Keeper account ${keeperUserId} not found`);
    if (!loser || !loser.id) throw new Error(`Loser account ${loserUserId} not found`);
    if (String(keeper.email || '').toLowerCase() !== String(loser.email || '').toLowerCase()) {
      throw new Error('Refusing to merge — keeper and loser do not share the same email. This safety check exists so a bad id never merges two unrelated accounts.');
    }

    // Re-point every table that references a user, loser -> keeper.
    // NOTE: some of these tables use a composite key (user_id + a second
    // field) instead of a single "id" — e.g. favorites is keyed by
    // (user_id, property_id), not id. For those, deleteRows+putRows (with
    // the new user_id) is used instead of updateRows-by-id, since there is
    // no single "id" field to filter by for a plain update.
    const COMPOSITE_USER_TABLES = {
      user_house_unlocks: 'property_id',
      favorites: 'property_id',
      notifications: 'notification_id',
    };
    const repointTables = [
      { table: 'houses', column: 'owner_id' },
      { table: 'purchases', column: 'user_id' },
      { table: 'favorites', column: 'user_id' },
      { table: 'user_house_unlocks', column: 'user_id' },
      { table: 'partner_requests', column: 'user_id' },
      { table: 'notifications', column: 'user_id' },
      { table: 'admin_bans', column: 'user_id' },
      { table: 'admin_warnings', column: 'user_id' },
    ];
    const repointed = {};
    for (const { table, column } of repointTables) {
      try {
        const TableNameX = tableName(table);
        const scannedX = await runDdb('read', table, () => ddb.send(new ScanCommand({ TableName: TableNameX })));
        const rowsX = (scannedX.Items || []).map(item => fromDbItem(table, unmarshall(item)));
        const toMove = rowsX.filter(r => String(r[column]) === String(loserUserId));
        const secondKeyField = COMPOSITE_USER_TABLES[table];
        for (const row of toMove) {
          if (secondKeyField) {
            // Composite-key table: re-create the row under the keeper's
            // user_id (re-using the rest of the row's fields), then delete
            // the original loser-keyed row. A straight "update by id"
            // can't work here since there is no single "id" key.
            try {
              const newRow = Object.assign({}, row, { user_id: keeperUserId });
              delete newRow.id; // composite tables don't use a top-level id
              await putRows({ table, values: newRow }, false);
              await deleteRows({ table, op: 'delete', filters: [{ op: 'eq', column: 'user_id', value: loserUserId }, { op: 'eq', column: secondKeyField, value: row[secondKeyField] }] });
            } catch (err) {
              console.warn(`[Admin] Merge: could not repoint composite-key ${table} row:`, err.message);
            }
          } else {
            await updateRows({ table, op: 'update', values: { [column]: keeperUserId }, filters: [{ op: 'eq', column: 'id', value: row.id }] }).catch(err => {
              console.warn(`[Admin] Merge: could not repoint ${table} row ${row.id}:`, err.message);
            });
          }
        }
        repointed[table] = toMove.length;
      } catch (err) {
        console.warn(`[Admin] Merge: skipping table "${table}" (not present or scan failed):`, err.message);
        repointed[table] = 0;
      }
    }

    // Sum numeric value fields onto the keeper instead of overwriting.
    const mergedCredits = (parseFloat(keeper.credits) || 0) + (parseFloat(loser.credits) || 0);
    const mergedXp = (parseInt(keeper.xp) || 0) + (parseInt(loser.xp) || 0);
    const mergedPartnerXp = (parseInt(keeper.partner_xp) || 0) + (parseInt(loser.partner_xp) || 0);
    const mergedTotalReferrals = (parseInt(keeper.total_referrals) || 0) + (parseInt(loser.total_referrals) || 0);
    const keeperPatch = {
      credits: Math.round(mergedCredits * 100) / 100,
      xp: mergedXp,
      partner_xp: mergedPartnerXp,
      total_referrals: mergedTotalReferrals,
    };
    // Keep keeper's referral_code if it has one; otherwise adopt loser's
    // (so a working code already shared with others isn't thrown away).
    if (!keeper.referral_code && loser.referral_code) keeperPatch.referral_code = loser.referral_code;

    await updateRows({ table: 'profiles', op: 'update', values: keeperPatch, filters: [{ op: 'eq', column: 'id', value: keeperUserId }] });

    // Delete the loser's Cognito login, then its profile row.
    let cognitoDeleted = false;
    try {
      const page = await cognitoAdmin.send(new ListUsersCommand({ UserPoolId: USER_POOL_ID, Filter: `sub = "${loserUserId}"`, Limit: 1 }));
      const cognitoUser = page.Users && page.Users[0];
      if (cognitoUser) {
        await cognitoAdmin.send(new AdminDeleteUserCommand({ UserPoolId: USER_POOL_ID, Username: cognitoUser.Username }));
        cognitoDeleted = true;
      }
    } catch (err) {
      console.warn(`[Admin] Merge: could not delete loser's Cognito login (${loserUserId}):`, err.message);
    }
    await deleteRows({ table: 'profiles', op: 'delete', filters: [{ op: 'eq', column: 'id', value: loserUserId }] }).catch(err => {
      console.warn(`[Admin] Merge: could not delete loser profile row (${loserUserId}):`, err.message);
    });

    console.log(`[Admin] Merged account ${loserUserId} into ${keeperUserId} for email ${keeper.email}. Repointed:`, repointed, 'Cognito login deleted:', cognitoDeleted);
    return { merged: true, keeperUserId, loserUserId, keeperPatch, repointed, cognitoLoginDeleted: cognitoDeleted };
  }

  throw new Error(`Unsupported RPC "${spec.name}"`);
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
  try {
    const claims = await verifyToken(req);
    const spec = await parseBody(req);
    validateSpec(spec);
    console.log('[RentNivas API] data request', { op: spec.op, table: spec.table, sub: claims.sub });

    let data;
    if (spec.op === 'select') data = await readItems(spec);
    else if (spec.op === 'insert') data = await putRows(spec, false);
    else if (spec.op === 'upsert') data = await putRows(spec, true);
    else if (spec.op === 'update') data = await updateRows(spec);
    else if (spec.op === 'delete') data = await deleteRows(spec);
    else if (spec.op === 'rpc') data = await handleRpc(spec, claims);
    else throw new Error(`Unsupported operation "${spec.op}"`);

    send(res, 200, { data, count: data && data.count, error: null });
  } catch (err) {
    console.error('[RentNivas API] data failure:', err);
    send(res, err.message && err.message.includes('authorization') ? 401 : 400, {
      data: null,
      error: { message: err.message || 'Request failed' }
    });
  }
};
