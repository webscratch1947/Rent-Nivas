const crypto = require('crypto');
const { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand, DeleteItemCommand, ScanCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'eu-north-1_GM7Zi2xvq';
const APP_CLIENT_ID = process.env.COGNITO_APP_CLIENT_ID || 'ckpmh0heco2apoh0temn8hfnl';
const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;
const JWKS_URL = `${ISSUER}/.well-known/jwks.json`;

const ddb = new DynamoDBClient({ region: REGION });
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
  houses: process.env.TABLE_HOUSES || 'Houses',
  Houses: process.env.TABLE_HOUSES || 'Houses',
  listing_questions: process.env.TABLE_LISTING_QUESTIONS || 'ListingQuestions',
  answers: process.env.TABLE_ANSWERS || 'Answers',
  admin_announcements: process.env.TABLE_ADMIN_ANNOUNCEMENTS || 'AdminAnnouncements',
  admin_warnings: process.env.TABLE_ADMIN_WARNINGS || 'AdminWarnings',
  warning_views: process.env.TABLE_WARNING_VIEWS || 'WarningViews',
  announcement_views: process.env.TABLE_ANNOUNCEMENT_VIEWS || 'AnnouncementViews',
  admin_bans: process.env.TABLE_ADMIN_BANS || 'AdminBans',
  admin_appeals: process.env.TABLE_ADMIN_APPEALS || 'AdminAppeals'
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

function keyFor(table, row, filters) {
  const all = Object.assign({}, row || {});
  (filters || []).forEach(f => {
    if (f.op === 'eq') all[f.column] = f.value;
  });
  if (table === 'partner_task_progress' || table === 'PartnerTaskProgress') {
    if (!all.task_id || !all.user_id) throw new Error('PartnerTaskProgress requires task_id and user_id');
    return { task_id: all.task_id, user_id: all.user_id };
  }
  if (table === 'answers') {
    if (!all.purchase_id || !all.question_id) throw new Error('Answers requires purchase_id and question_id');
    return { purchase_id: all.purchase_id, question_id: all.question_id };
  }
  if (table === 'warning_views') {
    if (!all.user_id || !all.warning_id) throw new Error('WarningViews requires user_id and warning_id');
    return { user_id: all.user_id, warning_id: all.warning_id };
  }
  if (table === 'announcement_views') {
    if (!all.user_id || !all.announcement_id) throw new Error('AnnouncementViews requires user_id and announcement_id');
    return { user_id: all.user_id, announcement_id: all.announcement_id };
  }
  if (!all.id && all.user_id && (table === 'partner_requests' || table === 'partner_applications' || table === 'PartnerApplications')) {
    all.id = all.user_id;
  }
  if (!all.id) throw new Error(`${table} requires id`);
  return { id: all.id };
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
    const got = await ddb.send(new GetItemCommand({ TableName, Key: marshall(key) }));
    const row = got.Item ? pickColumns(unmarshall(got.Item), spec.select) : null;
    return spec.single || spec.maybeSingle ? row : (row ? [row] : []);
  }
  const scanned = await ddb.send(new ScanCommand({ TableName }));
  let rows = (scanned.Items || []).map(item => unmarshall(item));
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

async function putRows(spec, merge) {
  const TableName = tableName(spec.table);
  const inputRows = Array.isArray(spec.values) ? spec.values : [spec.values];
  const saved = [];
  for (const row of inputRows) {
    const now = new Date().toISOString();
    const next = Object.assign({}, row);
    if (!next.id && !['partner_task_progress','PartnerTaskProgress','answers','warning_views','announcement_views'].includes(spec.table)) next.id = crypto.randomUUID();
    if (!next.created_at) next.created_at = now;
    next.updated_at = now;
    if (merge) {
      const key = keyFor(spec.table, next, spec.filters);
      const existing = await ddb.send(new GetItemCommand({ TableName, Key: marshall(key) }));
      const merged = Object.assign(existing.Item ? unmarshall(existing.Item) : {}, next, key);
      await ddb.send(new PutItemCommand({ TableName, Item: marshall(merged, { removeUndefinedValues: true }) }));
      saved.push(merged);
    } else {
      await ddb.send(new PutItemCommand({ TableName, Item: marshall(next, { removeUndefinedValues: true }) }));
      saved.push(next);
    }
  }
  return spec.single ? saved[0] : saved;
}

async function updateRows(spec) {
  const TableName = tableName(spec.table);
  const patch = Object.assign({}, spec.values || {}, { updated_at: new Date().toISOString() });
  const key = keyFor(spec.table, patch, spec.filters);
  const names = {};
  const values = {};
  const sets = [];
  Object.entries(patch).forEach(([k, v], i) => {
    if (Object.prototype.hasOwnProperty.call(key, k) || typeof v === 'undefined') return;
    names[`#k${i}`] = k;
    values[`:v${i}`] = v;
    sets.push(`#k${i} = :v${i}`);
  });
  if (!sets.length) return spec.single ? null : [];
  const result = await ddb.send(new UpdateItemCommand({
    TableName,
    Key: marshall(key),
    UpdateExpression: `SET ${sets.join(', ')}`,
    ExpressionAttributeNames: names,
    ExpressionAttributeValues: marshall(values, { removeUndefinedValues: true }),
    ReturnValues: 'ALL_NEW'
  }));
  const row = result.Attributes ? unmarshall(result.Attributes) : null;
  return spec.single || spec.maybeSingle ? row : (row ? [row] : []);
}

async function deleteRows(spec) {
  const TableName = tableName(spec.table);
  const key = keyFor(spec.table, {}, spec.filters);
  await ddb.send(new DeleteItemCommand({ TableName, Key: marshall(key) }));
  return [];
}

async function handleRpc(spec, claims) {
  if (spec.name === 'process_registration_referral') {
    const code = String((spec.params && spec.params.p_referral_code) || '').trim();
    if (!code) return { processed: false };
    const users = await readItems({ table: 'profiles', op: 'select', select: 'id,email,name,referral_code', filters: [{ op: 'eq', column: 'referral_code', value: code }], maybeSingle: true });
    if (!users || !users.id || users.id === claims.sub) return { processed: false };
    await updateRows({ table: 'profiles', op: 'update', values: { referred_by_code: code, referred_by_user_id: users.id }, filters: [{ op: 'eq', column: 'id', value: claims.sub }] });
    return { processed: true, referrer_id: users.id };
  }
  if (spec.name === 'award_referral_reward') {
    throw new Error('award_referral_reward requires a Houses/Listings DynamoDB table mapping. No such table was included in the provided AWS infrastructure list.');
  }
  throw new Error(`Unsupported RPC "${spec.name}"`);
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
  try {
    const claims = await verifyToken(req);
    const spec = await parseBody(req);
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



