const { S3Client, PutObjectCommand, DeleteObjectsCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const { REGION, send, parseBody, verifyToken } = require('./_auth');

const s3 = new S3Client({ region: REGION });
const BUCKET = process.env.S3_BUCKET || process.env.RENT_NIVAS_S3_BUCKET;
const PUBLIC_BASE_URL = process.env.S3_PUBLIC_BASE_URL || (BUCKET ? `https://${BUCKET}.s3.${REGION}.amazonaws.com` : '');

function ensureBucket() {
  if (!BUCKET) throw new Error('S3_BUCKET environment variable is required for image storage');
}

function normalizePath(path) {
  return String(path || '').replace(/^\/+/, '').replace(/\.\./g, '');
}

function decodeDataUrl(dataUrl) {
  const match = String(dataUrl || '').match(/^data:([^;]+);base64,(.*)$/);
  if (!match) throw new Error('Invalid upload body');
  return { contentType: match[1], body: Buffer.from(match[2], 'base64') };
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });
  try {
    ensureBucket();
    await verifyToken(req);
    const body = await parseBody(req);
    const op = body.op;

    if (op === 'upload') {
      const key = normalizePath(body.path);
      if (!key) throw new Error('Upload path is required');
      const file = decodeDataUrl(body.file);
      await s3.send(new PutObjectCommand({
        Bucket: BUCKET,
        Key: key,
        Body: file.body,
        ContentType: body.contentType || file.contentType,
        CacheControl: body.cacheControl || 'max-age=3600',
        ACL: process.env.S3_UPLOAD_ACL || undefined
      }));
      return send(res, 200, { data: { path: key, publicUrl: `${PUBLIC_BASE_URL}/${encodeURI(key)}` }, error: null });
    }

    if (op === 'remove') {
      const paths = (body.paths || []).map(normalizePath).filter(Boolean);
      if (!paths.length) return send(res, 200, { data: [], error: null });
      await s3.send(new DeleteObjectsCommand({
        Bucket: BUCKET,
        Delete: { Objects: paths.map(Key => ({ Key })) }
      }));
      return send(res, 200, { data: paths.map(path => ({ path })), error: null });
    }

    if (op === 'list') {
      const prefix = normalizePath(body.prefix || '');
      const listed = await s3.send(new ListObjectsV2Command({ Bucket: BUCKET, Prefix: prefix }));
      return send(res, 200, {
        data: (listed.Contents || []).map(obj => ({ name: obj.Key, id: obj.ETag, updated_at: obj.LastModified, metadata: { size: obj.Size } })),
        error: null
      });
    }

    throw new Error(`Unsupported storage operation "${op}"`);
  } catch (err) {
    console.error('[RentNivas] storage failed:', err);
    send(res, /authorization|token/i.test(err.message || '') ? 401 : 400, { data: null, error: { message: err.message || 'Storage request failed' } });
  }
};
