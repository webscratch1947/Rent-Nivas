const crypto = require('crypto');
const { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, DeleteItemCommand, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
// Used only by admin_merge_duplicate_accounts, to remove the loser
// account's Cognito login once its data has been moved to the keeper.
const { CognitoIdentityProviderClient, ListUsersCommand, AdminDeleteUserCommand } = require('@aws-sdk/client-cognito-identity-provider');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const APP_CLIENT_ID = process.env.COGNITO_APP_CLIENT_ID;
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

// ── NEW Referrals table ────────────────────────────────────────────────────────
// Partition key: referralId (S) = the referral code itself.
// Tracks referral history, counts, and owner identity in one place.
// NOT part of the TABLES map because it is accessed directly via raw DDB calls
// (no app-level id→PK renaming needed — the PK is already the referral code).
const TABLE_REFERRALS = process.env.TABLE_REFERRALS || 'Referrals';

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
    // Use numeric comparison when both values are numeric (fixes credits sort —
    // string comparison makes "9.5" > "25" because "9" > "2", causing wrong rank order)
    const an = parseFloat(av);
    const bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) {
      if (an < bn) return -1 * dir;
      if (an > bn) return 1 * dir;
      return 0;
    }
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
    let item = got.Item;
    // LEGACY KEY FALLBACK: mirror the fix already applied in putRows/updateRows.
    // Some accounts were created before the partition key was renamed from
    // "id" to "userId". A direct GetItem on {userId: x} finds nothing for
    // those rows, which previously made the caller think the profile didn't
    // exist at all and auto-create a fresh one (credits reset to 10, a brand
    // new random referral_code, etc) — silently shadowing the real row.
    // Fall back to the old {id: x} key before giving up.
    if (!item && key.userId && partitionKeyName(spec.table) === 'userId') {
      const legacyKey = { id: key.userId };
      const legacyGot = await runDdb('read', spec.table, () => ddb.send(new GetItemCommand({ TableName, Key: marshall(legacyKey) })));
      item = legacyGot.Item;
    }
    const row = item ? pickColumns(fromDbItem(spec.table, unmarshall(item)), spec.select) : null;
    return spec.single || spec.maybeSingle ? row : (row ? [row] : []);
  }
  const scanned = await runDdb('read', spec.table, () => ddb.send(new ScanCommand({ TableName })));
  let rows = (scanned.Items || []).map(item => fromDbItem(spec.table, unmarshall(item)));
  rows = applyFilters(rows, spec.filters);
  rows = applyOrder(rows, spec.order);
  if (spec.limit) rows = rows.slice(0, spec.limit);
  // FIX: always include the order column in the returned data, even if it was
  // not listed in spec.select.  Without this, a leaderboard query like
  //   .select('id,name,avatar_url').order('credits', {ascending:false})
  // strips 'credits' from every row via pickColumns, so the frontend receives
  // undefined for credits and falls back to displaying the default value (10).
  const orderCol = spec.order && spec.order.column;
  rows = rows.map(row => {
    const picked = pickColumns(row, spec.select);
    if (orderCol && picked && spec.select && spec.select !== '*' &&
        !String(spec.select).split(',').map(s => s.trim()).includes(orderCol) &&
        Object.prototype.hasOwnProperty.call(row, orderCol)) {
      picked[orderCol] = row[orderCol];
    }
    return picked;
  });
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
// NOTE: referral_code is NO LONGER auto-generated here. It is created on
// demand when the user first opens the Referral panel (get_or_create_referral_code
// RPC), which also creates the corresponding row in the Referrals table.
// Referral counters (total_referrals, registration_referrals, listing_referrals)
// now live ONLY in the Referrals table — not on the Users row.
const NEW_ROW_DEFAULTS = {
  profiles: {
    credits: 10,
    xp: 0,
    partner_xp: 0,
    chest_claimed: false,
    referred_by_code: null,
    daily_streak_day: 0,
    daily_streak_claimed_at: null,
    pending_referral_code: null,
  },
  users: { credits: 10, xp: 0, partner_xp: 0, referred_by_code: null, daily_streak_day: 0, daily_streak_claimed_at: null, pending_referral_code: null },
  Users: { credits: 10, xp: 0, partner_xp: 0, referred_by_code: null, daily_streak_day: 0, daily_streak_claimed_at: null, pending_referral_code: null },
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
      let existingAppRow = existing.Item ? fromDbItem(spec.table, unmarshall(existing.Item)) : {};
      let isFirstCreation = !existing.Item;

      // LEGACY KEY FIX: Some profiles were created before the partition key
      // was renamed from "id" to "userId".  When a upsert targets { userId: xxx }
      // and finds no row, it previously created a brand-new row with the correct
      // key but WITHOUT any of the fields (name, email, referral_code…) that
      // live only on the legacy "id"-keyed row.  That left two rows for the same
      // user — the new one with updated credits but no name, the old one with a
      // name but stale credits — which is exactly why the leaderboard showed 10
      // credits for users the admin had set to 25.
      //
      // Fix: when a userId-keyed lookup returns nothing, check whether a legacy
      // id-keyed row exists for the same user.  If found, use it as the base,
      // merge the caller's data on top, and write back under the correct
      // userId key — effectively migrating the row on first touch.  We also
      // delete the old id-keyed row so future operations never see the duplicate.
      if (isFirstCreation && partitionKeyName(spec.table) === 'userId' && next.id) {
        try {
          const legacyKey = { id: next.id };
          const legacyRes = await runDdb('upsert', spec.table, () =>
            ddb.send(new GetItemCommand({ TableName, Key: marshall(legacyKey) })));
          if (legacyRes.Item) {
            const legacyRow = unmarshall(legacyRes.Item);
            // CRITICAL: strip referral identity fields from legacy rows.
            // If this row belonged to a deleted account and someone re-registers
            // with the same email, we must NOT carry over referral_code or
            // referred_by_code — doing so causes the new user to inherit all
            // referral history of the old account.
            delete legacyRow.referral_code;
            delete legacyRow.referred_by_code;
            delete legacyRow.referred_by_user_id;
            delete legacyRow.total_referrals;
            delete legacyRow.registration_referrals;
            delete legacyRow.listing_referrals;
            delete legacyRow.daily_streak_day;
            delete legacyRow.daily_streak_claimed_at;
            // Strip old referral identity fields from legacy rows.
            // If this row belonged to a deleted account and someone re-registers
            // with the same email, we must NOT carry over referral_code or
            // referred_by_code — doing so causes the new user to inherit all
            // referral history of the old account.
            delete legacyRow.referral_code;
            delete legacyRow.referred_by_code;
            delete legacyRow.referred_by_user_id;
            delete legacyRow.daily_streak_day;
            delete legacyRow.daily_streak_claimed_at;
            existingAppRow = Object.assign({}, legacyRow, { id: next.id });
            isFirstCreation = false;
            // Remove the old id-keyed row to prevent duplicates in scans / leaderboard
            await runDdb('upsert', spec.table, () =>
              ddb.send(new DeleteItemCommand({ TableName, Key: marshall(legacyKey) })));
            console.log(`[RentNivas API] Migrated legacy id-keyed row to userId-keyed for table "${spec.table}", user:`, next.id);
          }
        } catch (legacyErr) {
          // Non-fatal — if migration check fails, proceed with normal first-creation
          console.warn('[RentNivas API] Legacy row migration check failed:', legacyErr.message);
        }
      }

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
      // Row didn't exist under the userId key — check if it exists under the
      // LEGACY "id" key (some older accounts were created before the key rename).
      // If a legacy row exists, update THAT row instead of creating a ghost duplicate.
      const pkName = partitionKeyName(spec.table);
      if (pkName === 'userId' && key.userId) {
        try {
          const legacyKey = { id: key.userId };
          const legacyRes = await runDdb('update', spec.table, () =>
            ddb.send(new GetItemCommand({ TableName, Key: marshall(legacyKey) }))
          );
          if (legacyRes && legacyRes.Item) {
            // Legacy row exists — update it directly (don't touch the userId key)
            console.log(`[RentNivas API] Found legacy id-keyed row for "${spec.table}" — updating legacy row instead of creating a ghost duplicate.`);
            const legacySets = [];
            const legacyNames = {};
            const legacyValues = {};
            Object.entries(patch).forEach(([k, v], i) => {
              if (k === 'id' || typeof v === 'undefined') return;
              legacyNames[`#lk${i}`] = k;
              legacyValues[`:lv${i}`] = v;
              legacySets.push(`#lk${i} = :lv${i}`);
            });
            if (legacySets.length) {
              const legacyResult = await runDdb('update', spec.table, () =>
                ddb.send(new UpdateItemCommand({
                  TableName,
                  Key: marshall(legacyKey),
                  UpdateExpression: `SET ${legacySets.join(', ')}`,
                  ExpressionAttributeNames: legacyNames,
                  ExpressionAttributeValues: marshall(legacyValues, { removeUndefinedValues: true }),
                  ReturnValues: 'ALL_NEW',
                }))
              );
              const row = legacyResult.Attributes ? fromDbItem(spec.table, unmarshall(legacyResult.Attributes)) : null;
              return spec.single || spec.maybeSingle ? row : (row ? [row] : []);
            }
          }
        } catch (legacyErr) {
          console.warn('[RentNivas API] Legacy key lookup failed:', legacyErr.message);
        }
      }
      // No legacy row found either. For the Users/profiles table specifically,
      // DO NOT silently create a brand-new row here: this code path is reached
      // by plain .update() calls (credits edits, etc) that often have nothing
      // but {credits: X} to write — no name/email — so a fabricated row here
      // is exactly how the "Anonymous, 150 credits" ghost rows on the
      // leaderboard got created (admin gives credits to a userId whose row
      // was concurrently purged as an orphan/duplicate). Fail loudly instead
      // so the caller (e.g. Edit Credits) can tell the admin to refresh.
      if (spec.table === 'profiles' || spec.table === 'users' || spec.table === 'Users') {
        console.warn(`[RentNivas API] update() target row didn't exist for "${spec.table}" (key=${JSON.stringify(key)}) — refusing to silently create a blank ghost row.`);
        throw new Error('This user\'s profile row no longer exists (it may have just been auto-removed as a duplicate/orphan). Refresh the user list and try again.');
      }
      // Every other table: create it properly (with full NEW_ROW_DEFAULTS) —
      // this is the legitimate first-write-race case (e.g. favoriting/unlocking
      // before the profile-creation upsert has finished).
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
// REFERRAL SYSTEM HELPERS  (v2 — Referrals table)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Check whether a given user_id has an accepted Partner Panel application.
 * Returns true if PartnerApplications contains a row with status = 'accepted'.
 */
async function hasPartnerAccess(userId) {
  try {
    const TableName = tableName('partner_requests');
    const scanned = await runDdb('read', 'partner_requests', () =>
      ddb.send(new ScanCommand({ TableName }))
    );
    const rows = (scanned.Items || []).map(i => unmarshall(i));
    return rows.some(r =>
      (r.user_id === userId || r.userId === userId) && r.status === 'accepted'
    );
  } catch (err) {
    console.error('[Referral] hasPartnerAccess check failed:', err.message);
    return false;
  }
}

/**
 * Award a referral reward to `referrerId`. Flat rate, same for every trigger
 * (registration OR house listing):
 *   - Has an accepted Partner Panel application → +5 XP
 *   - Otherwise                                  → +0.50 credits
 *
 * `kind` is just 'registration' | 'listing' for logging purposes — it does
 * NOT change the reward amount anymore (both used to differ: 15/10 XP —
 * that asymmetry is gone, this is the one true reward path now).
 *
 * Only modifies the profiles row (credits / xp / partner_xp).
 * Referral counts (totalReferrals etc.) are incremented separately by the
 * calling RPC handler against the Referrals table.
 */
async function awardReferralReward(referrerId, kind) {
  const isPartner = await hasPartnerAccess(referrerId);

  const referrer = await readItems({
    table: 'profiles',
    op: 'select',
    select: 'id,xp,credits,partner_xp',
    filters: [{ op: 'eq', column: 'id', value: referrerId }],
    maybeSingle: true,
  });

  if (!referrer || !referrer.id) {
    throw new Error(`Referrer profile not found for id=${referrerId}`);
  }

  let patch = { updated_at: new Date().toISOString() };
  let rewardDesc;

  const currentCredits = parseFloat(referrer.credits || 0);
  patch.credits = Math.round((currentCredits + 0.50) * 100) / 100;

  if (isPartner) {
    const currentXP        = parseInt(referrer.xp || 0, 10);
    const currentPartnerXP = parseInt(referrer.partner_xp || 0, 10);
    patch.xp         = currentXP + 5;
    patch.partner_xp = currentPartnerXP + 5;
    rewardDesc = `+5 XP · +0.50 credits (partner ${kind} referral)`;
  } else {
    rewardDesc = `+0.50 credits (${kind} referral)`;
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
// REFERRALS TABLE HELPER
// Ensures a Referrals table record exists for `userId` with the given `code`.
// Called lazily inside get_or_create_referral_code so every user who opens
// the Referral panel gets a canonical Referrals row in the new table.
// ─────────────────────────────────────────────────────────────────────────────
async function ensureReferralsRecord(code, userId, userName, userEmail) {
  try {
    // Check if record already exists
    const existing = await ddb.send(new GetItemCommand({
      TableName: TABLE_REFERRALS,
      Key: marshall({ referralId: code }),
    }));
    if (existing.Item) return; // already exists — nothing to do

    // Create a fresh record for this user
    await ddb.send(new PutItemCommand({
      TableName: TABLE_REFERRALS,
      Item: marshall({
        referralId:            code,
        userId:                userId,
        userName:              userName || '',
        userEmail:             userEmail || '',
        active:                true,
        totalReferrals:        0,
        registrationReferrals: 0,
        listingReferrals:      0,
        referredUsers:         [],
        referredListings:      [],
        createdAt:             new Date().toISOString(),
      }, { removeUndefinedValues: true }),
      // Only create if it still doesn't exist (guard against concurrent calls)
      ConditionExpression: 'attribute_not_exists(referralId)',
    }));
    console.log(`[Referral] Created Referrals table record for user ${userId} with code ${code}`);
  } catch (err) {
    // ConditionalCheckFailed = another request already created it (race) — fine
    if (err.name && err.name.includes('ConditionalCheckFailed')) return;
    console.warn('[Referral] ensureReferralsRecord failed (non-fatal):', err.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC HANDLER
// ─────────────────────────────────────────────────────────────────────────────
async function handleRpc(spec, claims) {

  // ── process_registration_referral ─────────────────────────────────────────
  // Called once per new user on their first login.
  // Idempotent: stamps Users.referred_by_code on the new user so a second
  // call (same session refresh) is a no-op.
  // ALL tracking data is stored in the Referrals table (v2).
  if (spec.name === 'process_registration_referral') {
    let code = String((spec.params && spec.params.p_referral_code) || '').trim().toUpperCase();

    // Collect caller's email for VerificationCodes fallback lookups
    let userEmail = String(claims.email || '').trim().toLowerCase();

    // Fallback 1: pending_referral_code written to Users profile by signup-verify.js
    if (!code) {
      try {
        const selfProfile = await readItems({
          table: 'profiles',
          op: 'select',
          select: 'id,email,pending_referral_code',
          filters: [{ op: 'eq', column: 'id', value: claims.sub }],
          maybeSingle: true,
        });
        if (selfProfile && selfProfile.pending_referral_code) {
          code = String(selfProfile.pending_referral_code).trim().toUpperCase();
          console.log('[Referral] Using pending_referral_code from profile for user ' + claims.sub + ': ' + code);
        }
        if (!userEmail && selfProfile && selfProfile.email) {
          userEmail = String(selfProfile.email).trim().toLowerCase();
        }
      } catch (e) {
        console.warn('[Referral] Could not read pending_referral_code:', e.message);
      }
    }

    // Fallback 2: pendingReferralCode stored in VerificationCodes by signup-verify.js
    if (!code && userEmail) {
      try {
        const TABLE_CODES = process.env.TABLE_VERIFICATION_CODES || 'VerificationCodes';
        const pk = `signup_verify#${userEmail}`;
        const vcRes = await ddb.send(new GetItemCommand({ TableName: TABLE_CODES, Key: marshall({ pk }) }));
        if (vcRes.Item) {
          const vcItem = unmarshall(vcRes.Item);
          if (vcItem.pendingReferralCode) {
            code = String(vcItem.pendingReferralCode).trim().toUpperCase();
            console.log('[Referral] Using pendingReferralCode from VerificationCodes for user ' + claims.sub + ' (' + userEmail + '): ' + code);
          }
        }
      } catch (e) {
        console.warn('[Referral] Could not read pendingReferralCode from VerificationCodes:', e.message);
      }
    }

    if (!code) return { processed: false, reason: 'no_code' };

    // ── Idempotency guard: check if this user was already referred ──────────
    const newUserProfile = await readItems({
      table: 'profiles',
      op: 'select',
      select: 'id,name,email,avatar_url,referred_by_code',
      filters: [{ op: 'eq', column: 'id', value: claims.sub }],
      maybeSingle: true,
    });
    if (newUserProfile && newUserProfile.referred_by_code) {
      console.log(`[Referral] Registration referral already processed for user ${claims.sub} — skipping`);
      return { processed: false, reason: 'already_processed' };
    }

    // ── Look up referrer in the Referrals table (fast GetItem by code) ──────
    let refItem = null;
    try {
      const refRes = await ddb.send(new GetItemCommand({
        TableName: TABLE_REFERRALS,
        Key: marshall({ referralId: code }),
      }));
      if (refRes.Item) refItem = unmarshall(refRes.Item);
    } catch (e) {
      console.warn('[Referral] Referrals table lookup failed, trying Users fallback:', e.message);
    }

    // Fallback: code may still only exist in the Users table (pre-migration user)
    let referrerId = refItem && refItem.userId;
    if (!referrerId) {
      const legacyReferrer = await readItems({
        table: 'profiles',
        op: 'select',
        select: 'id,name,email,referral_code',
        filters: [{ op: 'eq', column: 'referral_code', value: code }],
        maybeSingle: true,
      });
      if (legacyReferrer && legacyReferrer.id) referrerId = legacyReferrer.id;
    }

    if (!referrerId || referrerId === claims.sub) {
      return { processed: false, reason: 'referrer_not_found' };
    }

    if (refItem && refItem.active === false) {
      return { processed: false, reason: 'inactive_code' };
    }

    // ── Update Referrals table: append new user entry, increment counts ──────
    const newUserEntry = {
      userId:   claims.sub,
      name:     (newUserProfile && newUserProfile.name)       || (userEmail ? userEmail.split('@')[0] : ''),
      email:    (newUserProfile && newUserProfile.email)      || userEmail || '',
      avatar:   (newUserProfile && newUserProfile.avatar_url) || '',
      joinedAt: new Date().toISOString(),
    };

    try {
      // Guard: check if this user is already in referredUsers (extra idempotency)
      const existingUsers = (refItem && refItem.referredUsers) || [];
      const alreadyAdded  = existingUsers.some(u => u && u.userId === claims.sub);
      if (!alreadyAdded) {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_REFERRALS,
          Key: marshall({ referralId: code }),
          UpdateExpression:
            'SET referredUsers = list_append(if_not_exists(referredUsers, :empty), :newUser),' +
            '    totalReferrals        = if_not_exists(totalReferrals, :zero)        + :one,' +
            '    registrationReferrals = if_not_exists(registrationReferrals, :zero) + :one',
          ExpressionAttributeValues: marshall({
            ':newUser': [newUserEntry],
            ':empty':   [],
            ':zero':    0,
            ':one':     1,
          }, { removeUndefinedValues: true }),
        }));
      }
    } catch (e) {
      // Non-fatal — reward still gets applied; counts will be off but won't block the user
      console.warn('[Referral] Could not update Referrals table entry:', e.message);
    }

    // ── Stamp new user with referred_by_code (ATOMIC — conditional write) ──────
    // Uses a ConditionExpression so that if two concurrent calls both passed the
    // earlier guard, only ONE of them actually writes (and therefore awards).
    // The other hits ConditionalCheckFailedException and returns 'already_processed'.
    try {
      const TBL_USERS = tableName('profiles');
      // Try userId key, then legacy id key
      let profileKey = null;
      for (const k of [{ userId: claims.sub }, { id: claims.sub }]) {
        try {
          const chk = await ddb.send(new GetItemCommand({ TableName: TBL_USERS, Key: marshall(k) }));
          if (chk.Item) { profileKey = k; break; }
        } catch (_) {}
      }
      if (profileKey) {
        const pkField = Object.keys(profileKey)[0];
        await ddb.send(new UpdateItemCommand({
          TableName: TBL_USERS,
          Key: marshall(profileKey),
          UpdateExpression: 'SET referred_by_code = :code, referred_by_user_id = :rid',
          ConditionExpression: 'attribute_not_exists(referred_by_code)',
          ExpressionAttributeValues: marshall({ ':code': code, ':rid': referrerId }),
        }));
      } else {
        // Fallback if key not found — use updateRows (not atomic but better than nothing)
        await updateRows({
          table: 'profiles', op: 'update',
          values: { referred_by_code: code, referred_by_user_id: referrerId },
          filters: [{ op: 'eq', column: 'id', value: claims.sub }],
        });
      }
    } catch (stampErr) {
      const stampCode = stampErr && (stampErr.name || '');
      if (/ConditionalCheckFailed/i.test(stampCode)) {
        // Another concurrent call already stamped referred_by_code — this call loses the race
        console.log(`[Referral] Concurrent registration referral race for user ${claims.sub} — this call lost; aborting`);
        return { processed: false, reason: 'already_processed' };
      }
      throw stampErr; // unexpected DDB error — let the outer handler surface it
    }

    // ── Award referrer (credits / XP on their Users row) ─────────────────────
    // Reached only by the one call that won the conditional stamp above.
    // FIX: this used to be a bare `await` with no try/catch. Since the new
    // user is stamped with referred_by_code BEFORE this line (irreversibly,
    // via the conditional write above), any error thrown here — e.g. a
    // transient DynamoDB hiccup, or the referrer's profile row not existing
    // under the expected key — used to bubble up as an unhandled 500 AND
    // permanently lose the reward, because a retry would see referred_by_code
    // already set and short-circuit with 'already_processed' without ever
    // re-attempting the award. Catch it, log loudly so it's traceable, and
    // still report success for the registration itself — but surface the
    // reward failure explicitly instead of losing it silently.
    let reward = null;
    try {
      reward = await awardReferralReward(referrerId, 'registration');
    } catch (rewardErr) {
      console.error(`[Referral] AWARD FAILED for referrer=${referrerId} new_user=${claims.sub} code=${code}:`, rewardErr);
      reward = { referrer_id: referrerId, error: rewardErr.message || 'Award failed' };
    }

    // ── Clear pending_referral_code so future calls are idempotent ────────────
    await updateRows({
      table: 'profiles',
      op: 'update',
      values: { pending_referral_code: null },
      filters: [{ op: 'eq', column: 'id', value: claims.sub }],
    }).catch(e => console.warn('[Referral] Could not clear pending_referral_code:', e.message));

    // ── Clean up VerificationCodes row ────────────────────────────────────────
    if (userEmail) {
      try {
        const TABLE_CODES = process.env.TABLE_VERIFICATION_CODES || 'VerificationCodes';
        await ddb.send(new DeleteItemCommand({ TableName: TABLE_CODES, Key: marshall({ pk: 'signup_verify#' + userEmail }) }));
      } catch (e) { console.warn('[Referral] Could not delete VerificationCodes row:', e.message); }
    }

    console.log(`[Referral] Registration referral processed: new_user=${claims.sub} referrer=${referrerId} code=${code}`);
    return { processed: true, referrer_id: referrerId, reward };
  }

  // ── award_listing_referral ───────────────────────────────────────────────
  // Called when a referred user publishes their first property listing.
  // p_house_id is passed; we look up the referral_code on the property,
  // then find the referrer via the Referrals table, and award them.
  // Duplicate-reward guard: a reward is only issued once per property.
  // ALL tracking data is stored in the Referrals table (v2).
  //
  // NOTE: this RPC name must match RPC_MAP.award_listing in index.html
  // exactly — a previous mismatch ('award_referral_reward' here vs.
  // 'award_listing_referral' on the client) meant every listing referral
  // silently 400'd with "Unsupported RPC" and no reward was ever given.
  if (spec.name === 'award_listing_referral') {
    const houseId = String((spec.params && spec.params.p_house_id) || '').trim();
    if (!houseId) return { awarded: false, reason: 'no_house_id' };

    // ── Fetch the property ─────────────────────────────────────────────────
    const house = await readItems({
      table: 'houses',
      op: 'select',
      select: 'id,referral_code,referral_reward_given,owner_id,title,images',
      filters: [{ op: 'eq', column: 'id', value: houseId }],
      maybeSingle: true,
    });

    if (!house || !house.id) return { awarded: false, reason: 'house_not_found' };

    // ── Duplicate-reward guard ────────────────────────────────────────────
    if (house.referral_reward_given) {
      console.log(`[Referral] Listing reward already given for house ${houseId} — skipping`);
      return { awarded: false, reason: 'already_awarded' };
    }

    const refCode = String(house.referral_code || '').trim().toUpperCase();
    if (!refCode) return { awarded: false, reason: 'no_referral_code' };

    // ── Look up referrer in the Referrals table ────────────────────────────
    let refItem = null;
    try {
      const refRes = await ddb.send(new GetItemCommand({
        TableName: TABLE_REFERRALS,
        Key: marshall({ referralId: refCode }),
      }));
      if (refRes.Item) refItem = unmarshall(refRes.Item);
    } catch (e) {
      console.warn('[Referral] Referrals table lookup failed for award, trying Users fallback:', e.message);
    }

    let referrerId = refItem && refItem.userId;
    if (!referrerId) {
      // Fallback: code still only in Users table (pre-migration referrer)
      const legacyReferrer = await readItems({
        table: 'profiles',
        op: 'select',
        select: 'id,referral_code',
        filters: [{ op: 'eq', column: 'referral_code', value: refCode }],
        maybeSingle: true,
      });
      if (legacyReferrer && legacyReferrer.id) referrerId = legacyReferrer.id;
    }

    if (!referrerId) return { awarded: false, reason: 'referrer_not_found' };

    // ── Self-referral guard ────────────────────────────────────────────────
    if (referrerId === house.owner_id || referrerId === claims.sub) {
      return { awarded: false, reason: 'self_referral' };
    }

    // ── Look up owner name for the Referrals record ────────────────────────
    let ownerName = '';
    try {
      const ownerProfile = await readItems({
        table: 'profiles', op: 'select', select: 'id,name',
        filters: [{ op: 'eq', column: 'id', value: house.owner_id }], maybeSingle: true,
      });
      ownerName = (ownerProfile && ownerProfile.name) || '';
    } catch (e) { /* non-fatal */ }

    // ── Mark listing as rewarded (ATOMIC — conditional write) ─────────────────
    // ConditionExpression ensures only ONE concurrent call actually sets the flag
    // (and therefore awards). The other hits ConditionalCheckFailedException.
    try {
      const TBL_HOUSES = tableName('houses');
      const PROP_PK = 'propertyId'; // actual DynamoDB partition key for Properties table
      await ddb.send(new UpdateItemCommand({
        TableName: TBL_HOUSES,
        Key: marshall({ [PROP_PK]: houseId }),
        UpdateExpression: 'SET referral_reward_given = :t',
        ConditionExpression: 'attribute_not_exists(referral_reward_given) OR referral_reward_given = :f',
        ExpressionAttributeValues: marshall({ ':t': true, ':f': false }),
      }));
    } catch (flagErr) {
      const flagCode = flagErr && (flagErr.name || '');
      if (/ConditionalCheckFailed/i.test(flagCode)) {
        // Another concurrent call already set the flag — this call loses the race
        console.log(`[Referral] Concurrent listing reward race for house ${houseId} — this call lost; aborting`);
        return { awarded: false, reason: 'already_awarded' };
      }
      // Unexpected error — try the non-atomic fallback so the flag still gets set
      console.warn('[Referral] Conditional reward flag failed, falling back to updateRows:', flagErr.message);
      await updateRows({
        table: 'houses', op: 'update',
        values: { referral_reward_given: true },
        filters: [{ op: 'eq', column: 'id', value: houseId }],
      });
    }

    // ── Update Referrals table: append listing entry, increment counts ─────
    const listingEntry = {
      listingId:  houseId,
      title:      house.title   || '',
      image:      (Array.isArray(house.images) && house.images[0]) || '',
      ownerId:    house.owner_id || '',
      ownerName,
      listedAt:   new Date().toISOString(),
    };

    try {
      const existingListings = (refItem && refItem.referredListings) || [];
      const alreadyAdded     = existingListings.some(l => l && l.listingId === houseId);
      if (!alreadyAdded) {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_REFERRALS,
          Key: marshall({ referralId: refCode }),
          UpdateExpression:
            'SET referredListings = list_append(if_not_exists(referredListings, :empty), :newListing),' +
            '    totalReferrals   = if_not_exists(totalReferrals, :zero)  + :one,' +
            '    listingReferrals = if_not_exists(listingReferrals, :zero) + :one',
          ExpressionAttributeValues: marshall({
            ':newListing': [listingEntry],
            ':empty':      [],
            ':zero':       0,
            ':one':        1,
          }, { removeUndefinedValues: true }),
        }));
      }
    } catch (e) {
      console.warn('[Referral] Could not update Referrals table for listing award:', e.message);
    }

    // ── Award the referrer (credits / XP on their Users row) ─────────────
    // Same fix as the registration path: the "already awarded" flag on the
    // house is already set above, so a bare throw here would permanently
    // lose the reward (a retry would just hit the "already_awarded" guard
    // and never re-attempt the award). Catch and surface instead.
    let reward = null;
    try {
      reward = await awardReferralReward(referrerId, 'listing');
    } catch (rewardErr) {
      console.error(`[Referral] AWARD FAILED for referrer=${referrerId} house=${houseId} code=${refCode}:`, rewardErr);
      reward = { referrer_id: referrerId, error: rewardErr.message || 'Award failed' };
    }

    console.log(`[Referral] Listing referral reward given: house=${houseId} referrer=${referrerId} code=${refCode}`);
    return { awarded: true, referrer_id: referrerId, reward };
  }

  // ── admin_backfill_missed_rewards ────────────────────────────────────────
  // One-time (safe to re-run) sweep that pays out rewards that were silently
  // lost to two now-fixed bugs:
  //   1. reward_owner_for_unlock queried a nonexistent 'properties' table,
  //      so NO owner ever got their unlock credit until this was fixed.
  //   2. award_listing_referral was called under the wrong RPC name
  //      ('award_referral_reward'), so NO house-listing referral ever paid
  //      out until the name mismatch was fixed.
  //   3. Partner referrers used to receive XP only (no credits) for every
  //      referral, before the rule changed to XP + credits. This tops up
  //      the missing 0.50/referral for partners who were shorted.
  // Every step here reuses the exact same idempotency guards as the live
  // code path (house.referral_reward_given, purchase.owner_rewarded), so
  // this can be run repeatedly with no risk of double-paying anyone.
  if (spec.name === 'admin_backfill_missed_rewards') {
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean);
    const isAdminCaller = (claims['cognito:groups'] || []).includes('admin') || adminEmails.includes(String(claims.email || '').toLowerCase());
    if (!isAdminCaller) throw new Error('Admin access required');

    const result = {
      ownerRewardsPaid: 0, ownerRewardsSkipped: 0, ownerRewardsFailed: 0,
      listingReferralsPaid: 0, listingReferralsSkipped: 0, listingReferralsFailed: 0,
      partnerTopUpsPaid: 0, partnerTopUpsSkipped: 0, partnerTopUpsFailed: 0,
    };

    // Fake "admin" claims to reuse the existing RPC handlers' internal logic
    // without a real end-user session attached to each historical event.
    const adminClaims = { sub: '__backfill__', email: '', 'cognito:groups': ['admin'] };

    // ── 1. Missed owner-unlock rewards ──────────────────────────────────────
    try {
      const purchasesTbl = tableName('purchases');
      const scanned = await runDdb('read', 'purchases', () => ddb.send(new ScanCommand({ TableName: purchasesTbl })));
      const purchases = (scanned.Items || []).map(item => fromDbItem('purchases', unmarshall(item)));
      for (const p of purchases) {
        if (p.owner_rewarded) { result.ownerRewardsSkipped++; continue; }
        if (!p.id || !p.listing_id) { result.ownerRewardsSkipped++; continue; }
        try {
          const res = await handleRpc({
            name: 'reward_owner_for_unlock',
            params: { property_id: p.listing_id, purchase_id: p.id, buyer_id: p.user_id },
          }, adminClaims);
          if (res && res.rewarded) result.ownerRewardsPaid++;
          else result.ownerRewardsSkipped++;
        } catch (e) {
          console.error('[Backfill] owner reward failed for purchase', p.id, e.message);
          result.ownerRewardsFailed++;
        }
      }
    } catch (e) {
      console.error('[Backfill] purchases scan failed:', e.message);
    }

    // ── 2. Missed house-listing referral rewards ────────────────────────────
    try {
      const housesTbl = tableName('houses');
      const scanned = await runDdb('read', 'houses', () => ddb.send(new ScanCommand({ TableName: housesTbl })));
      const houses = (scanned.Items || []).map(item => fromDbItem('houses', unmarshall(item)));
      for (const h of houses) {
        if (h.referral_reward_given) { result.listingReferralsSkipped++; continue; }
        if (!h.referral_code) { result.listingReferralsSkipped++; continue; }
        try {
          const res = await handleRpc({ name: 'award_listing_referral', params: { p_house_id: h.id } }, adminClaims);
          if (res && res.awarded) result.listingReferralsPaid++;
          else result.listingReferralsSkipped++;
        } catch (e) {
          console.error('[Backfill] listing referral failed for house', h.id, e.message);
          result.listingReferralsFailed++;
        }
      }
    } catch (e) {
      console.error('[Backfill] houses scan failed:', e.message);
    }

    // ── 3. Top up partner referrers who only got XP under the old rule ─────
    try {
      const scanned = await runDdb('read', 'Referrals', () => ddb.send(new ScanCommand({ TableName: TABLE_REFERRALS })));
      const referralRows = (scanned.Items || []).map(item => unmarshall(item));
      for (const r of referralRows) {
        if (!r.userId || r.regCreditTopUpApplied) { result.partnerTopUpsSkipped++; continue; }
        const regCount = parseInt(r.registrationReferrals || 0, 10);
        if (!regCount) { result.partnerTopUpsSkipped++; continue; }
        try {
          const isPartner = await hasPartnerAccess(r.userId);
          if (!isPartner) {
            // Not a partner — under both the old and new rule they already
            // got their 0.50 credits at the time, nothing owed. Just stamp
            // so we don't re-check this row every time the sweep runs.
            await ddb.send(new UpdateItemCommand({
              TableName: TABLE_REFERRALS, Key: marshall({ referralId: r.referralId }),
              UpdateExpression: 'SET regCreditTopUpApplied = :t',
              ExpressionAttributeValues: marshall({ ':t': true }),
            }));
            result.partnerTopUpsSkipped++;
            continue;
          }
          const owedCredits = Math.round(regCount * 0.50 * 100) / 100;
          const referrerProfile = await readItems({
            table: 'profiles', op: 'select', select: 'id,credits',
            filters: [{ op: 'eq', column: 'id', value: r.userId }], maybeSingle: true,
          });
          if (!referrerProfile) { result.partnerTopUpsFailed++; continue; }
          const newCredits = Math.round((parseFloat(referrerProfile.credits || 0) + owedCredits) * 100) / 100;
          await updateRows({
            table: 'profiles', op: 'update',
            values: { credits: newCredits, updated_at: new Date().toISOString() },
            filters: [{ op: 'eq', column: 'id', value: r.userId }],
          });
          await ddb.send(new UpdateItemCommand({
            TableName: TABLE_REFERRALS, Key: marshall({ referralId: r.referralId }),
            UpdateExpression: 'SET regCreditTopUpApplied = :t',
            ExpressionAttributeValues: marshall({ ':t': true }),
          }));
          console.log(`[Backfill] Topped up partner ${r.userId} with ${owedCredits} missed referral credits`);
          result.partnerTopUpsPaid++;
        } catch (e) {
          console.error('[Backfill] partner top-up failed for referral row', r.referralId, e.message);
          result.partnerTopUpsFailed++;
        }
      }
    } catch (e) {
      console.error('[Backfill] Referrals scan failed:', e.message);
    }

    console.log('[Backfill] admin_backfill_missed_rewards result:', result);
    return result;
  }

  // ── claim_daily_reward ────────────────────────────────────────────────────
  // Awards 1 credit per day × 7 days = 7 credits per cycle. 24-hour cooldown.
  // After day 7 the cycle resets to day 1. Idempotent within the 24h window.
  if (spec.name === 'claim_daily_reward') {
    const userId = claims.sub;
    const profile = await readItems({
      table: 'profiles', op: 'select',
      select: 'id,credits,daily_streak_day,daily_streak_claimed_at',
      filters: [{ op: 'eq', column: 'id', value: userId }],
      maybeSingle: true,
    });
    if (!profile || !profile.id) throw new Error('Profile not found');

    const now = Date.now();
    const streakDay = parseInt(profile.daily_streak_day || '0', 10);
    const lastClaimedAt = profile.daily_streak_claimed_at ? new Date(profile.daily_streak_claimed_at).getTime() : 0;
    const DAY_MS = 24 * 60 * 60 * 1000;

    if (lastClaimedAt > 0 && (now - lastClaimedAt) < DAY_MS) {
      return { claimed: false, reason: 'too_soon', ms_until_next: DAY_MS - (now - lastClaimedAt), current_day: streakDay };
    }

    const nextDay = streakDay >= 7 ? 1 : streakDay + 1;
    const CREDITS_PER_DAY = [1, 2, 3, 4, 5, 6, 7];
    const creditsToAdd = CREDITS_PER_DAY[nextDay - 1];
    const currentCredits = parseFloat(profile.credits || '0');
    const newCredits = Math.round((currentCredits + creditsToAdd) * 100) / 100;

    await updateRows({
      table: 'profiles', op: 'update',
      values: { daily_streak_day: nextDay, daily_streak_claimed_at: new Date(now).toISOString(), credits: newCredits },
      filters: [{ op: 'eq', column: 'id', value: userId }],
    });

    console.log('[DailyReward] User ' + userId + ' claimed day ' + nextDay + ' — +' + creditsToAdd + ' credits, new balance: ' + newCredits);
    return { claimed: true, day: nextDay, credits_awarded: creditsToAdd, new_credits: newCredits };
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
    const rawItems = (scanned.Items || []).map(item => unmarshall(item));

    // ── MERGE LEGACY-ID-KEYED + USERID-KEYED DUPLICATE ROWS ──
    // The actual root cause of "admin/leaderboard shows correct credits but
    // the user's own dashboard is stuck at an old/lower number": some accounts
    // have TWO physical rows — one stored under the old "id" attribute
    // (created before the partition key was renamed) and one under "userId"
    // (created later, sometimes with a stale/lower credits value from the
    // old auto-create-on-missing-profile bug). The dashboard does a direct
    // single-row GetItem on the userId key, so it only ever sees the newer
    // row — even when the legacy row has the real, higher credit balance.
    // Leaderboard/admin scans see both rows and surface the best value,
    // which is why they looked "correct" while the dashboard didn't.
    // This merges every such pair: keeps the higher credits (and fills in
    // any field missing on the userId row from the legacy row), writes it
    // onto the canonical userId-keyed row, then deletes the legacy row so
    // there is only ever one row per user going forward.
    const legacyById = {};   // id -> raw legacy item (has 'id', no 'userId')
    const currentById = {};  // id -> raw current item (has 'userId')
    rawItems.forEach(it => {
      if (Object.prototype.hasOwnProperty.call(it, 'userId') && it.userId) {
        currentById[it.userId] = it;
      } else if (Object.prototype.hasOwnProperty.call(it, 'id') && it.id) {
        legacyById[it.id] = it;
      }
    });
    let mergedDuplicates = 0;
    for (const uid of Object.keys(legacyById)) {
      const legacy = legacyById[uid];
      const current = currentById[uid];
      if (!current) continue; // only legacy row exists — readItems fallback already handles this case
      const legacyCredits = parseFloat(legacy.credits);
      const currentCredits = parseFloat(current.credits);
      const bestCredits = Math.max(isNaN(legacyCredits) ? 0 : legacyCredits, isNaN(currentCredits) ? 0 : currentCredits);
      const merged = Object.assign({}, legacy, current); // current wins on conflicts...
      merged.credits = bestCredits;                       // ...except credits, always the higher one
      if (!merged.referral_code && legacy.referral_code) merged.referral_code = legacy.referral_code;
      if ((!merged.name || merged.name === 'User') && legacy.name) merged.name = legacy.name;
      delete merged.id; // 'id' isn't a real attribute on the userId-keyed item
      merged.userId = uid;
      merged.updated_at = new Date().toISOString();
      try {
        await ddb.send(new PutItemCommand({ TableName, Item: marshall(merged, { removeUndefinedValues: true }) }));
        await ddb.send(new DeleteItemCommand({ TableName, Key: marshall({ id: uid }) }));
        mergedDuplicates++;
        console.log(`[Admin] Merged duplicate rows for user ${uid}: credits ${currentCredits} + legacy ${legacyCredits} -> ${bestCredits}`);
      } catch (e) {
        console.warn(`[Admin] Failed to merge duplicate rows for user ${uid}:`, e.message);
      }
    }

    const rows = rawItems.map(item => fromDbItem('profiles', item));
    let fixed = 0;
    let creditsTopped = 0;
    for (const row of rows) {
      if (!row.id) continue;
      // Backfill basic profile defaults (credits, xp, partner_xp, name) for
      // any rows that are missing them. Referral counters live in the Referrals
      // table now — we no longer touch total_referrals/registration_referrals
      // /listing_referrals on the Users row.
      const patch = {};
      if (!row.name && row.email) patch.name = row.email.split('@')[0];
      if (row.partner_xp === undefined || row.partner_xp === null) patch.partner_xp = 0;
      const currentCredits = parseFloat(row.credits);
      if (isNaN(currentCredits) || row.credits === undefined || row.credits === null) {
        patch.credits = 10;
      }
      if (Object.keys(patch).length > 0) {
        try {
          await updateRows({
            table: 'profiles', op: 'update',
            values: patch,
            filters: [{ op: 'eq', column: 'id', value: row.id }],
          });
          fixed++;
        } catch (e) {
          console.warn(`[Admin] Could not patch profile ${row.id}:`, e.message);
        }
      }
      // One-time admin top-up: give every account at least 10 credits.
      const effectiveCredits = parseFloat(row.credits) || 0;
      if (effectiveCredits < 10 && !patch.credits) {
        await updateRows({
          table: 'profiles',
          op: 'update',
          values: { credits: 10 },
          filters: [{ op: 'eq', column: 'id', value: row.id }],
        });
        creditsTopped++;
      }
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

    // ── CREATE TRULY MISSING ROWS ──────────────────────────────────────────
    // Everything above only fixes/tops-up rows that already exist in
    // DynamoDB. But several accounts have NO row at all (the fire-and-forget
    // client-side profile-creation call on first login silently failed for
    // them at some point) — those show up everywhere as "0 credits" because
    // there's nothing in the table to read. Find every Cognito user with no
    // matching Users row and create one now with the normal new-account
    // defaults (10 credits etc), instead of leaving them permanently broken
    // until they happen to log out and back in again.
    let created = 0;
    try {
      const knownIds = new Set(rows.map(r => String(r.id || '')));
      let pt;
      do {
        const page = await cognitoAdmin.send(new ListUsersCommand({ UserPoolId: USER_POOL_ID, Limit: 60, PaginationToken: pt }));
        for (const u of page.Users || []) {
          const a = (u.Attributes || []).reduce((acc, x) => { acc[x.Name] = x.Value; return acc; }, {});
          const sub = a.sub;
          if (!sub || knownIds.has(sub)) continue;
          try {
            await putRows({
              table: 'profiles',
              values: {
                id: sub,
                name: a.name || (a.email ? a.email.split('@')[0] : 'User'),
                email: a.email || '',
                created_at: u.UserCreateDate ? new Date(u.UserCreateDate).toISOString() : new Date().toISOString(),
              },
              single: true,
            }, true);
            knownIds.add(sub);
            created++;
            console.log('[Admin] Created missing profile row for Cognito user with no DynamoDB row:', sub, a.email || '');
          } catch (e) {
            console.warn('[Admin] Failed to create missing profile row for', sub, ':', e.message);
          }
        }
        pt = page.PaginationToken;
      } while (pt);
    } catch (e) {
      console.warn('[Admin] Could not scan Cognito users to create missing rows:', e.message);
    }

    return { scanned: rows.length, fixed, dedupedUsers, deletedRows, mergedDuplicates, created };
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

    // AUTHORITATIVE EMAIL LOOKUP: a profile row's own `email` attribute can be
    // blank or stale (e.g. rows auto-created mid-race during Google sign-in
    // never had it filled in), which made this scanner miss real duplicates —
    // even ones plainly visible with the same email in the admin user list,
    // because that list gets its emails from Cognito, not from this field.
    // Pull every user's real email straight from Cognito (by their sub, which
    // is the same value as the profile row's id) so grouping is correct even
    // when the DB row itself never recorded an email.
    const cognitoEmailBySub = {};
    try {
      let PaginationToken;
      do {
        const page = await cognitoAdmin.send(new ListUsersCommand({ UserPoolId: USER_POOL_ID, Limit: 60, PaginationToken }));
        (page.Users || []).forEach(u => {
          const a = (u.Attributes || []).reduce((acc, x) => { acc[x.Name] = x.Value; return acc; }, {});
          const sub = a.sub || u.Username;
          if (sub && a.email) cognitoEmailBySub[sub] = String(a.email).trim().toLowerCase();
        });
        PaginationToken = page.PaginationToken;
      } while (PaginationToken);
    } catch (e) {
      console.warn('[Admin] Could not fetch Cognito users for duplicate scan, falling back to DB email field only:', e.message);
    }

    const byEmail = {};
    rows.forEach(r => {
      const dbEmail = String(r.email || '').trim().toLowerCase();
      const email = cognitoEmailBySub[r.id] || dbEmail; // prefer Cognito's authoritative email
      if (!email) return;
      (byEmail[email] = byEmail[email] || []).push({
        id: r.id, name: r.name, email: r.email || email, credits: r.credits,
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
    const mergedCredits   = (parseFloat(keeper.credits) || 0) + (parseFloat(loser.credits) || 0);
    const mergedXp        = (parseInt(keeper.xp) || 0) + (parseInt(loser.xp) || 0);
    const mergedPartnerXp = (parseInt(keeper.partner_xp) || 0) + (parseInt(loser.partner_xp) || 0);
    // NOTE: total_referrals, registration_referrals, listing_referrals are NOT
    // merged here because they now live only in the Referrals table, not on
    // the Users row. The Referrals record is keyed by referral code, not by
    // userId — whoever keeps the code keeps the history.
    const keeperPatch = {
      credits:    Math.round(mergedCredits * 100) / 100,
      xp:         mergedXp,
      partner_xp: mergedPartnerXp,
    };
    // Keep keeper's referral_code if it has one; otherwise adopt loser's
    // (so a working code already shared with others isn't thrown away).
    // Also update the Referrals table record to point to the keeper's userId.
    if (!keeper.referral_code && loser.referral_code) {
      keeperPatch.referral_code = loser.referral_code;
      // Re-point the Referrals record to keeper's userId
      try {
        await ddb.send(new UpdateItemCommand({
          TableName: TABLE_REFERRALS,
          Key: marshall({ referralId: loser.referral_code }),
          UpdateExpression: 'SET userId = :uid',
          ExpressionAttributeValues: marshall({ ':uid': keeperUserId }),
        }));
      } catch (e) {
        console.warn('[Admin] Merge: could not re-point Referrals record to keeper:', e.message);
      }
    }

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

  // ── get_unlock_reward_rate ────────────────────────────────────────────────
  // Returns the platform setting: how many credits the property OWNER receives
  // when a renter unlocks their listing. Default = 1 (full credit passes through).
  // Admin can set this to e.g. 0.8 meaning owner gets 0.8 credits per unlock.
  // Stored in DynamoDB Users table under a special row userId='__platform_settings__'
  if (spec.name === 'get_unlock_reward_rate') {
    try {
      const settingsRow = await readItems({
        table: 'profiles',
        op: 'select',
        select: 'unlock_owner_reward_rate',
        filters: [{ op: 'eq', column: 'id', value: '__platform_settings__' }],
        maybeSingle: true,
      });
      const rate = settingsRow && settingsRow.unlock_owner_reward_rate !== undefined
        ? parseFloat(settingsRow.unlock_owner_reward_rate)
        : 1;
      return { rate: isNaN(rate) ? 1 : rate };
    } catch (e) {
      return { rate: 1 };
    }
  }

  // ── set_unlock_reward_rate ────────────────────────────────────────────────
  // Admin-only. Sets how many credits the owner receives per unlock.
  if (spec.name === 'set_unlock_reward_rate') {
    const isAdminCaller = (claims['cognito:groups'] || []).includes('admin') ||
      (process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean)
        .includes(String(claims.email || '').toLowerCase());
    if (!isAdminCaller) throw new Error('Admin access required');
    const rate = parseFloat((spec.params && spec.params.rate) || 1);
    if (isNaN(rate) || rate < 0 || rate > 10) throw new Error('Rate must be a number between 0 and 10');
    // Store in a special platform settings row
    const TBL = tableName('profiles');
    const { marshall } = require('@aws-sdk/util-dynamodb');
    const { PutItemCommand } = require('@aws-sdk/client-dynamodb');
    await ddb.send(new PutItemCommand({
      TableName: TBL,
      Item: marshall({ userId: '__platform_settings__', unlock_owner_reward_rate: rate }),
    }));
    console.log('[SetUnlockRate] unlock_owner_reward_rate set to', rate);
    return { rate };
  }

  // ── reward_owner_for_unlock ───────────────────────────────────────────────
  // Called by the frontend immediately after a successful unlock purchase.
  // Finds the property owner and adds credits * unlock_owner_reward_rate to them.
  // Idempotent via the purchase_id check — won't double-reward if called twice.
  if (spec.name === 'reward_owner_for_unlock') {
    const { property_id, purchase_id, buyer_id } = spec.params || {};
    if (!property_id || !purchase_id) throw new Error('reward_owner_for_unlock requires property_id and purchase_id');

    // Verify caller is the buyer (or admin)
    const isAdminCaller = (claims['cognito:groups'] || []).includes('admin') ||
      (process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean)
        .includes(String(claims.email || '').toLowerCase());
    if (!isAdminCaller && claims.sub !== buyer_id) throw new Error('Unauthorized');

    // Get the property to find owner_id
    const property = await readItems({
      table: 'houses',
      op: 'select',
      select: 'id,owner_id',
      filters: [{ op: 'eq', column: 'id', value: property_id }],
      maybeSingle: true,
    });
    if (!property || !property.owner_id) {
      console.warn('[RewardOwner] property not found or no owner_id:', property_id);
      return { rewarded: false, reason: 'property_not_found' };
    }

    const ownerId = property.owner_id;

    // Don't reward if owner == buyer
    if (ownerId === claims.sub || ownerId === buyer_id) {
      return { rewarded: false, reason: 'self_unlock' };
    }

    // Check if this purchase was already rewarded (idempotency)
    const purchase = await readItems({
      table: 'purchases',
      op: 'select',
      select: 'id,owner_rewarded',
      filters: [{ op: 'eq', column: 'id', value: purchase_id }],
      maybeSingle: true,
    });
    if (purchase && purchase.owner_rewarded) {
      return { rewarded: false, reason: 'already_rewarded' };
    }

    // Get reward rate
    let rate = 1;
    try {
      const settingsRow = await readItems({
        table: 'profiles',
        op: 'select',
        select: 'unlock_owner_reward_rate',
        filters: [{ op: 'eq', column: 'id', value: '__platform_settings__' }],
        maybeSingle: true,
      });
      if (settingsRow && settingsRow.unlock_owner_reward_rate !== undefined) {
        rate = parseFloat(settingsRow.unlock_owner_reward_rate);
        if (isNaN(rate)) rate = 1;
      }
    } catch (e) { rate = 1; }

    // Get owner's current credits
    const ownerProfile = await readItems({
      table: 'profiles',
      op: 'select',
      select: 'id,credits,listing_referrals',
      filters: [{ op: 'eq', column: 'id', value: ownerId }],
      maybeSingle: true,
    });
    if (!ownerProfile) {
      console.warn('[RewardOwner] owner profile not found:', ownerId);
      return { rewarded: false, reason: 'owner_not_found' };
    }

    const currentCredits = parseFloat(ownerProfile.credits || 0);
    const currentListingReferrals = parseInt(ownerProfile.listing_referrals || 0, 10);
    const newCredits = Math.round((currentCredits + rate) * 100) / 100;

    // Update owner credits atomically
    const { UpdateItemCommand } = require('@aws-sdk/client-dynamodb');
    const { marshall } = require('@aws-sdk/util-dynamodb');
    const TBL = tableName('profiles');
    await ddb.send(new UpdateItemCommand({
      TableName: TBL,
      Key: marshall({ userId: ownerId }),
      UpdateExpression: 'SET credits = :c, listing_referrals = :lr, updated_at = :ua',
      ExpressionAttributeValues: marshall({
        ':c': newCredits,
        ':lr': currentListingReferrals + 1,
        ':ua': new Date().toISOString(),
      }),
      ConditionExpression: 'attribute_exists(userId)',
    }));

    // Mark purchase as owner-rewarded so we never double-pay
    try {
      const PurchaseTBL = tableName('purchases');
      await ddb.send(new UpdateItemCommand({
        TableName: PurchaseTBL,
        Key: marshall({ id: purchase_id }),
        UpdateExpression: 'SET owner_rewarded = :t, owner_reward_rate = :r, owner_id = :oid',
        ExpressionAttributeValues: marshall({ ':t': true, ':r': rate, ':oid': ownerId }),
      }));
    } catch (e) {
      console.warn('[RewardOwner] Could not mark purchase as rewarded:', e.message);
    }

    console.log('[RewardOwner] Owner', ownerId, 'rewarded', rate, 'credits for unlock of', property_id, '(purchase', purchase_id + ')');
    return { rewarded: true, owner_id: ownerId, credits_added: rate, new_credits: newCredits };
  }

    // ── get_leaderboard ───────────────────────────────────────────────────────
  // Returns users sorted by credits descending (numeric), with rank numbers.
  // This RPC is the single source of truth for leaderboard data because it:
  //   1. Sorts numerically (parseFloat) — fixes "9.5" > "25" string-sort bug
  //   2. Merges duplicate rows per user (legacy id-keyed + new userId-keyed rows)
  //      by taking MAX credits and the best available name — this was the root
  //      cause of "admin sets 25 credits, leaderboard shows 10": the upsert
  //      created a second nameless row with 25 credits while the original named
  //      row kept 10; the old fetch then filtered out the nameless row and showed
  //      the old credits for everyone
  //   3. Always returns credits as a JS number, never undefined/null/string
  if (spec.name === 'get_leaderboard') {
    const TableName = tableName('profiles');
    const scanned = await runDdb('read', 'profiles', () => ddb.send(new ScanCommand({ TableName })));
    const rawRows = (scanned.Items || []).map(item => {
      const r = unmarshall(item);
      // Normalise: both legacy (id-keyed) and current (userId-keyed) rows must
      // surface under the same 'id' field so de-dup works correctly.
      // Track which format each row is so we can choose credits correctly below.
      const isLegacy = !Object.prototype.hasOwnProperty.call(r, 'userId') && Object.prototype.hasOwnProperty.call(r, 'id');
      const effectiveId = r.userId || r.id || '';
      return Object.assign({}, r, { id: effectiveId, _isLegacy: isLegacy });
    });

    // De-duplicate by user ID.
    // Root cause of the credits mismatch:
    //   Legacy profile rows use 'id' as the DynamoDB partition key and hold
    //   the original default credits (10).  When an admin sets credits via upsert,
    //   the backend keyed on 'userId' and — if the legacy row existed — created a
    //   SECOND row with the correct new credits but no name.  Two rows now exist
    //   for the same user:
    //     • legacy row  → { id: 'xxx', name: 'MGR', credits: 10 }  (old)
    //     • current row → { userId: 'xxx', credits: 5 }             (admin-set)
    //
    //   Previous merge used Math.max, which returned 10 when admin set 5.
    //
    //   Fix: PREFER the non-legacy (userId-keyed) row's credits because that is
    //   the row the admin explicitly wrote to.  The legacy row's credits are just
    //   the old default and must not override the intentional admin update.
    const byId = {};
    for (const row of rawRows) {
      const uid = String(row.id || '');
      if (!uid) continue;
      if (!byId[uid]) {
        byId[uid] = row;
      } else {
        const prev = byId[uid];
        // Decide which row's credits to trust:
        //   • Non-legacy (userId-keyed) row wins — it was the target of the last admin write.
        //   • If both are the same type, trust the more recently updated one.
        let credits;
        const prevIsLegacy = prev._isLegacy;
        const currIsLegacy = row._isLegacy;
        if (!currIsLegacy && prevIsLegacy) {
          credits = parseFloat(row.credits) || 0;   // current row is authoritative
        } else if (currIsLegacy && !prevIsLegacy) {
          credits = parseFloat(prev.credits) || 0;  // prev row is authoritative
        } else {
          // Both same format — trust whichever was updated most recently
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
          // Take name/avatar from whichever row actually has them
          name: (prev.name && prev.name.trim()) ? prev.name : (row.name || ''),
          avatar_url: prev.avatar_url || row.avatar_url || null,
          _isLegacy: false,
        };
      }
    }

    // Sort by credits NUMERICALLY descending
    const merged = Object.values(byId);
    merged.sort((a, b) => (parseFloat(b.credits) || 0) - (parseFloat(a.credits) || 0));

    const limit = spec.params && spec.params.limit ? parseInt(spec.params.limit, 10) : 300;
    const top = merged.slice(0, limit);

    // Attach rank numbers and return only public-safe fields
    const result = top.map((row, idx) => ({
      rank: idx + 1,
      id: row.id || '',
      name: row.name || '',
      avatar_url: row.avatar_url || null,
      credits: parseFloat(row.credits) || 0,
      xp: parseInt(row.xp || '0', 10),
    }));

    console.log(`[Leaderboard] ${result.length} users returned; #1="${result[0] && result[0].name}" credits=${result[0] && result[0].credits}`);
    return result;
  }

  // ── admin_purge_ghost_rows ──────────────────────────────────────────────
  // Scans the Users table and deletes any row where the partition key (userId)
  // looks like an email address. These are ghost rows created by the old
  // signup-verify.js bug where cognitoUser.Username (the email string) was
  // used as the DynamoDB key instead of the real Cognito sub UUID.
  if (spec.name === 'admin_purge_ghost_rows') {
    const isAdminCaller = (claims['cognito:groups'] || []).includes('admin') ||
      (process.env.ADMIN_EMAILS || '').split(',').map(v => v.trim().toLowerCase()).filter(Boolean)
        .includes(String(claims.email || '').toLowerCase());
    if (!isAdminCaller) throw new Error('Admin access required');

    const TableName = tableName('Users');
    const scanned_result = await ddb.send(new ScanCommand({ TableName }));
    const items = scanned_result.Items || [];
    let deleted = 0;

    // Also fetch every real Cognito sub so we can catch true orphan rows —
    // a valid-UUID-keyed row with no matching Cognito user at all. These are
    // exactly the nameless "Anonymous" ghost rows that admin credit-edits
    // used to fabricate when targeting a stale/already-removed userId.
    const validSubs = new Set();
    try {
      let pt;
      do {
        const page = await cognitoAdmin.send(new ListUsersCommand({ UserPoolId: USER_POOL_ID, Limit: 60, PaginationToken: pt }));
        (page.Users || []).forEach(u => {
          const sub = (u.Attributes || []).find(a => a.Name === 'sub');
          if (sub && sub.Value) validSubs.add(sub.Value);
        });
        pt = page.PaginationToken;
      } while (pt);
    } catch (err) {
      console.warn('[PurgeGhosts] Could not list Cognito users for orphan check:', err.message);
    }

    for (const item of items) {
      const row = unmarshall(item);
      const uid = String(row.userId || row.id || '');
      // Ghost rows have userId = email string (contains @)
      const isEmailKeyed = uid.includes('@');
      // Orphan rows: a real-looking key but no matching Cognito user anymore
      const isOrphan = !isEmailKeyed && uid && validSubs.size > 0 && !validSubs.has(uid);
      if (isEmailKeyed || isOrphan) {
        try {
          const keyToDelete = row.userId ? { userId: uid } : { id: uid };
          await ddb.send(new DeleteItemCommand({ TableName, Key: marshall(keyToDelete) }));
          console.log('[PurgeGhosts] Deleted', isOrphan ? 'orphan' : 'email-keyed ghost', 'row with userId:', uid);
          deleted++;
        } catch (delErr) {
          console.warn('[PurgeGhosts] Failed to delete ghost row:', uid, delErr.message);
        }
      }
    }

    console.log(`[PurgeGhosts] Scan complete — scanned ${items.length}, deleted ${deleted} ghost rows`);
    return { scanned: items.length, deleted };
  }

  // ── get_or_create_referral_code ─────────────────────────────────────────────
  // Reliable server-side referral code fetch/create (v2).
  //
  // 1. Reads the caller's Users profile (tries both key formats).
  // 2. If no referral_code exists, generates a fresh 8-char uppercase hex code
  //    derived from the user's Cognito sub (deterministic but not guessable).
  // 3. Saves the code onto the Users row for quick retrieval next time.
  // 4. Ensures a matching row exists in the Referrals table.
  //
  // The Referrals row is the canonical tracking store; the Users.referral_code
  // field is a denormalised pointer that avoids scanning Referrals.
  if (spec.name === 'get_or_create_referral_code') {
    const userId = claims.sub;
    if (!userId) throw Object.assign(new Error('Not authenticated'), { status: 401 });
    const TBL = tableName('profiles');

    // Try canonical userId key, then legacy id key
    let item    = null;
    let keyUsed = null;
    for (const k of [{ userId }, { id: userId }]) {
      try {
        const got = await ddb.send(new GetItemCommand({ TableName: TBL, Key: marshall(k) }));
        if (got.Item) { item = unmarshall(got.Item); keyUsed = k; break; }
      } catch (_) { /* try next key format */ }
    }

    let code = item && item.referral_code;

    if (!code) {
      // Derive a short, uppercase, URL-safe code from the user's sub.
      // Using crypto.createHash ensures the same user always gets the same code
      // even across multiple concurrent calls (deterministic — no random).
      code = String(parseInt(crypto.createHash('sha256').update(userId).digest('hex').slice(0, 13), 16) % 100000000).padStart(8, '0');

      if (keyUsed) {
        const pkField = Object.keys(keyUsed)[0];
        try {
          await ddb.send(new UpdateItemCommand({
            TableName: TBL,
            Key: marshall(keyUsed),
            UpdateExpression: 'SET referral_code = :code',
            ExpressionAttributeValues: marshall({ ':code': code }),
            ConditionExpression: `attribute_exists(${pkField})`,
          }));
          console.log('[RPC get_or_create_referral_code] Saved new referral code for', userId, ':', code);
        } catch (saveErr) {
          console.warn('[RPC get_or_create_referral_code] Could not save code to Users row:', saveErr.message);
          // Non-fatal — still return the code so the UI can display it
        }
      } else {
        console.warn('[RPC get_or_create_referral_code] Profile row not found for userId:', userId);
      }
    }

    // Ensure the Referrals table has a record for this code (lazy creation)
    if (code) {
      const userName  = (item && item.name)  || '';
      const userEmail = (item && item.email) || '';
      await ensureReferralsRecord(code, userId, userName, userEmail);
    }

    return { referral_code: code || null };
  }

  // ── get_referral_data ────────────────────────────────────────────────────────
  // Returns the caller's full referral profile from the Referrals table.
  // Used by the Referral Panel on the frontend to render history + counts.
  // Shape returned:
  //   {
  //     referralCode, active,
  //     totalReferrals, registrationReferrals, listingReferrals,
  //     referredUsers:    [{ userId, name, email, avatar, joinedAt }],
  //     referredListings: [{ listingId, title, image, ownerId, ownerName, listedAt }]
  //   }
  if (spec.name === 'get_referral_data') {
    const userId = claims.sub;
    if (!userId) throw Object.assign(new Error('Not authenticated'), { status: 401 });

    // Step 1: find the user's referral code from their Users row
    const TBL = tableName('profiles');
    let profileItem = null;
    for (const k of [{ userId }, { id: userId }]) {
      try {
        const got = await ddb.send(new GetItemCommand({ TableName: TBL, Key: marshall(k) }));
        if (got.Item) { profileItem = unmarshall(got.Item); break; }
      } catch (_) {}
    }

    const referralCode = profileItem && profileItem.referral_code;

    // No code yet → return empty shape (caller will run get_or_create_referral_code)
    if (!referralCode) {
      return {
        referralCode: null, active: true,
        totalReferrals: 0, registrationReferrals: 0, listingReferrals: 0,
        referredUsers: [], referredListings: [],
      };
    }

    // Step 2: fetch the Referrals table record
    try {
      const refRes = await ddb.send(new GetItemCommand({
        TableName: TABLE_REFERRALS,
        Key: marshall({ referralId: referralCode }),
      }));

      if (!refRes.Item) {
        // Referrals row doesn't exist yet — create it lazily, return empty counts
        const userName  = (profileItem && profileItem.name)  || '';
        const userEmail = (profileItem && profileItem.email) || '';
        await ensureReferralsRecord(referralCode, userId, userName, userEmail);
        return {
          referralCode, active: true,
          totalReferrals: 0, registrationReferrals: 0, listingReferrals: 0,
          referredUsers: [], referredListings: [],
        };
      }

      const refItem = unmarshall(refRes.Item);
      return {
        referralCode,
        active:                refItem.active !== false,
        totalReferrals:        parseInt(refItem.totalReferrals        || 0, 10),
        registrationReferrals: parseInt(refItem.registrationReferrals || 0, 10),
        listingReferrals:      parseInt(refItem.listingReferrals      || 0, 10),
        referredUsers:         Array.isArray(refItem.referredUsers)    ? refItem.referredUsers    : [],
        referredListings:      Array.isArray(refItem.referredListings) ? refItem.referredListings : [],
      };
    } catch (err) {
      console.warn('[RPC get_referral_data] Referrals lookup failed (returning empty):', err.message);
      return {
        referralCode, active: true,
        totalReferrals: 0, registrationReferrals: 0, listingReferrals: 0,
        referredUsers: [], referredListings: [],
      };
    }
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
