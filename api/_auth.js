const crypto = require('crypto');

const REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || 'eu-north-1_GM7Zi2xvq';
const APP_CLIENT_ID = process.env.COGNITO_APP_CLIENT_ID || 'ckpmh0heco2apoh0temn8hfnl';
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

module.exports = { REGION, USER_POOL_ID, APP_CLIENT_ID, send, parseBody, verifyToken, requireAdmin, isAdmin };
