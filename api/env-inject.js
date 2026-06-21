/**
 * Dynamic env-inject — served as /env-inject.js via vercel.json rewrite.
 * Reads server-side env vars so the frontend gets the correct S3 bucket URL
 * and Cognito config without hardcoding credentials in static files.
 */
module.exports = function handler(req, res) {
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  const region     = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
  const userPoolId = process.env.COGNITO_USER_POOL_ID || 'eu-north-1_GM7Zi2xvq';
  const clientId   = process.env.COGNITO_APP_CLIENT_ID || 'ckpmh0heco2apoh0temn8hfnl';
  const bucket     = process.env.S3_BUCKET || '';

  // Build the public S3 base URL — prefer an explicit env var, fall back to
  // constructing it from the bucket name + region.
  const s3PublicBase =
    process.env.S3_PUBLIC_BASE_URL ||
    (bucket ? `https://${bucket}.s3.${region}.amazonaws.com` : '');

  res.end(
    `window.__RN_AWS_REGION = '${region}';\n` +
    `window.__RN_COGNITO_USER_POOL_ID = '${userPoolId}';\n` +
    `window.__RN_COGNITO_CLIENT_ID = '${clientId}';\n` +
    `window.__RN_S3_PUBLIC_BASE_URL = '${s3PublicBase}';\n`
  );
};
