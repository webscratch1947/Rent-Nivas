/**
 * Dynamic env-inject — served as /env-inject.js via vercel.json rewrite.
 * GET (default): emits window.__RN_* JS vars (S3/Cognito config + site version).
 * GET ?json=1: same site-version data as plain JSON — used by cache-buster.js.
 * POST (admin-only): force-bumps the site version so every visitor (new and
 * returning) hard-refreshes and clears their cache within ~5 minutes.
 *
 * NOTE: this file intentionally also carries the site-version logic instead
 * of living in its own api/site-version.js file — the Vercel Hobby plan caps
 * deployments at 12 Serverless Functions, and this project is already at
 * that limit. Folding it in here (a file that's already loaded on every
 * page, for every visitor, unauthenticated) avoids needing a 13th function.
 */
const { DynamoDBClient, GetItemCommand, PutItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { REGION, send, requireAdmin } = require('./_auth');

const ddb = new DynamoDBClient({ region: REGION });
const SITE_CONFIG_TABLE = process.env.TABLE_SITE_CONFIG || 'SiteConfig';
const VERSION_PK = 'site_version';

// Short-lived in-memory cache so we don't hit DynamoDB on every single
// pageview — same pattern used for the JWKS cache in _auth.js.
let versionCache = null;
let versionCachedAt = 0;
const VERSION_CACHE_MS = 20 * 1000;

async function getSiteVersion() {
  if (versionCache && Date.now() - versionCachedAt < VERSION_CACHE_MS) return versionCache;
  // Falls back to this deploy's own commit SHA — Vercel sets this
  // automatically on every deploy — so versioning works even if SiteConfig
  // doesn't exist yet, and self-heals on every future deploy with no setup.
  let version = process.env.VERCEL_GIT_COMMIT_SHA || '0';
  try {
    const got = await ddb.send(new GetItemCommand({ TableName: SITE_CONFIG_TABLE, Key: marshall({ pk: VERSION_PK }) }));
    if (got.Item) {
      const item = unmarshall(got.Item);
      if (item.version) version = String(item.version);
    }
  } catch (e) {
    console.warn('[RentNivas] site-version read failed, using build SHA fallback:', e.message);
  }
  versionCache = version;
  versionCachedAt = Date.now();
  return version;
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});

  if (req.method === 'POST') {
    // Admin-only: force every visitor to hard-refresh right now.
    try {
      await requireAdmin(req);
      const newVersion = String(Date.now());
      await ddb.send(new PutItemCommand({
        TableName: SITE_CONFIG_TABLE,
        Item: marshall({ pk: VERSION_PK, version: newVersion, updatedAt: newVersion })
      }));
      versionCache = newVersion;
      versionCachedAt = Date.now();
      return send(res, 200, { ok: true, version: newVersion });
    } catch (err) {
      console.error('[RentNivas] site-version bump failed:', err);
      return send(res, /Admin access|authorization|token/i.test(err.message || '') ? 401 : 500, {
        error: err.message || 'Failed to bump site version'
      });
    }
  }

  const region     = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
  const userPoolId = process.env.COGNITO_USER_POOL_ID || 'eu-north-1_GM7Zi2xvq';
  const clientId   = process.env.COGNITO_APP_CLIENT_ID || 'ckpmh0heco2apoh0temn8hfnl';
  const bucket     = process.env.S3_BUCKET || '';
  const s3PublicBase =
    process.env.S3_PUBLIC_BASE_URL ||
    (bucket ? `https://${bucket}.s3.${region}.amazonaws.com` : '');
  const siteVersion = await getSiteVersion();

  let wantsJson = false;
  try { wantsJson = new URL(req.url, 'http://x').searchParams.get('json') === '1'; } catch (e) {}

  if (wantsJson) {
    return send(res, 200, { version: siteVersion });
  }

  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.end(
    `window.__RN_AWS_REGION = '${region}';\n` +
    `window.__RN_COGNITO_USER_POOL_ID = '${userPoolId}';\n` +
    `window.__RN_COGNITO_CLIENT_ID = '${clientId}';\n` +
    `window.__RN_S3_PUBLIC_BASE_URL = '${s3PublicBase}';\n` +
    `window.__RN_SITE_VERSION = '${siteVersion}';\n`
  );
};
