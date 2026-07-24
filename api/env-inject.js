/**
 * Dynamic env-inject — served as /env-inject.js via vercel.json rewrite, and
 * also reachable directly at /api/env-inject.js.
 *
 * GET (default): emits window.__RN_* JS vars (S3/Cognito/Google OAuth config
 * + site version). Every value comes from environment variables — nothing
 * here is hardcoded. If a required var is missing, the corresponding
 * window.__RN_* value is left empty and the dependent feature (e.g. Google
 * sign-in) will surface a clear "not configured" error instead of silently
 * falling back to some baked-in value.
 * GET ?json=1: same site-version data as plain JSON — used by cache-buster.js.
 * POST (admin-only): force-bumps the site version so every visitor (new and
 * returning) hard-refreshes and clears their cache within ~5 minutes.
 *
 * NOTE: this file intentionally also carries the site-version logic instead
 * of living in its own api/site-version.js file — the Vercel Hobby plan caps
 * deployments at 12 Serverless Functions, and this project is already at
 * that limit. Folding it in here (a file that's already loaded on every
 * page, for every visitor, unauthenticated) avoids needing a 13th function.
 * (A second, unreachable copy of this file used to live at the project root —
 * it required './_auth' from a path where that module doesn't exist, so it
 * could never have run. It's been removed to avoid duplicate config logic.)
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

  const region     = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION;
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  const clientId   = process.env.COGNITO_APP_CLIENT_ID;
  const bucket     = process.env.S3_BUCKET || '';
  const s3PublicBase =
    process.env.S3_PUBLIC_BASE_URL ||
    (bucket ? `https://${bucket}.s3.${region}.amazonaws.com` : '');

  // ── Google OAuth (brokered through the Cognito Hosted UI) ────────────────
  // Google sign-in here works as: browser -> Cognito Hosted UI /authorize
  // (identity_provider=Google) -> Google consent -> Cognito -> back to our
  // redirect_uri with ?code=. Cognito itself holds the actual Google
  // client_id/secret as an Identity Provider configuration in the AWS
  // console — this app never talks to Google's endpoints directly, so
  // GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are not consumed by this code.
  // GOOGLE_AUTH_URI / GOOGLE_TOKEN_URI default to Cognito's own
  // /oauth2/authorize and /oauth2/token endpoints (built from COGNITO_DOMAIN)
  // but can be overridden if you ever swap in a direct Google OAuth flow.
  const cognitoDomain = process.env.COGNITO_DOMAIN || '';
  const googleAuthUri = process.env.GOOGLE_AUTH_URI || (cognitoDomain ? `https://${cognitoDomain}/oauth2/authorize` : '');
  const googleTokenUri = process.env.GOOGLE_TOKEN_URI || (cognitoDomain ? `https://${cognitoDomain}/oauth2/token` : '');
  // Not currently called by this flow — Cognito's id_token already carries
  // the Google profile claims — but exposed for completeness/future use.
  const googleUserinfoUri = process.env.GOOGLE_USERINFO_URI || '';
  const googleScopes = process.env.GOOGLE_SCOPES || 'openid email profile';
  // COGNITO_REDIRECT_URI is the redirect_uri sent to Cognito's Hosted UI
  // (NOT a Google value — Cognito owns this redirect). Use this single env
  // var consistently; GOOGLE_REDIRECT_URI is no longer read here.
  const redirectUri = process.env.COGNITO_REDIRECT_URI || '';

  const siteVersion = await getSiteVersion();

  let wantsJson = false;
  try { wantsJson = new URL(req.url, 'http://x').searchParams.get('json') === '1'; } catch (e) {}

  if (wantsJson) {
    return send(res, 200, { version: siteVersion });
  }

  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.end(
    `window.__RN_AWS_REGION = ${JSON.stringify(region || '')};\n` +
    `window.__RN_COGNITO_USER_POOL_ID = ${JSON.stringify(userPoolId || '')};\n` +
    `window.__RN_COGNITO_CLIENT_ID = ${JSON.stringify(clientId || '')};\n` +
    `window.__RN_S3_PUBLIC_BASE_URL = ${JSON.stringify(s3PublicBase || '')};\n` +
    `window.__RN_COGNITO_DOMAIN = ${JSON.stringify(cognitoDomain)};\n` +
    `window.__RN_COGNITO_REDIRECT_URI = ${JSON.stringify(redirectUri)};\n` +
    `window.__RN_GOOGLE_AUTH_URI = ${JSON.stringify(googleAuthUri)};\n` +
    `window.__RN_GOOGLE_TOKEN_URI = ${JSON.stringify(googleTokenUri)};\n` +
    `window.__RN_GOOGLE_USERINFO_URI = ${JSON.stringify(googleUserinfoUri)};\n` +
    `window.__RN_GOOGLE_SCOPES = ${JSON.stringify(googleScopes)};\n` +
    `window.__RN_SITE_VERSION = ${JSON.stringify(siteVersion)};\n` +
    `window.__RN_ADMIN_EMAILS = ${JSON.stringify(process.env.ADMIN_EMAILS || "")};\n`
  );
};
