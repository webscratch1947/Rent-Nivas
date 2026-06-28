const { DynamoDBClient, GetItemCommand, PutItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { REGION, send, requireAdmin } = require('./_auth');

const ddb = new DynamoDBClient({ region: REGION });
const TABLE = process.env.TABLE_SITE_CONFIG || 'SiteConfig';
const PK = 'site_version';

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  // Belt & suspenders — Vercel functions aren't edge-cached by default anyway.
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');

  try {
    if (req.method === 'GET') {
      // Falls back to the build's own commit SHA — Vercel sets this automatically
      // on every deploy — so version-checking works even before SiteConfig exists.
      let version = process.env.VERCEL_GIT_COMMIT_SHA || String(0);
      try {
        const got = await ddb.send(new GetItemCommand({ TableName: TABLE, Key: marshall({ pk: PK }) }));
        if (got.Item) {
          const item = unmarshall(got.Item);
          if (item.version) version = String(item.version);
        }
      } catch (e) {
        console.warn('[RentNivas] site-version read failed, using build SHA fallback:', e.message);
      }
      return send(res, 200, { version });
    }

    if (req.method === 'POST') {
      // Admin-only: force every visitor (new and returning) to hard-refresh.
      await requireAdmin(req);
      const newVersion = String(Date.now());
      await ddb.send(new PutItemCommand({
        TableName: TABLE,
        Item: marshall({ pk: PK, version: newVersion, updatedAt: newVersion })
      }));
      return send(res, 200, { ok: true, version: newVersion });
    }

    return send(res, 405, { error: 'Method not allowed' });
  } catch (err) {
    console.error('[RentNivas] site-version failed:', err);
    send(res, /Admin access|authorization|token/i.test(err.message || '') ? 401 : 500, {
      error: err.message || 'Failed to read/update site version'
    });
  }
};
