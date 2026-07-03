const {
  CognitoIdentityProviderClient,
  AdminDeleteUserCommand,
  AdminGetUserCommand,
  ListUsersCommand
} = require('@aws-sdk/client-cognito-identity-provider');
const { DynamoDBClient, DeleteItemCommand, ScanCommand, UpdateItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { REGION, USER_POOL_ID, send, parseBody, requireAdmin } = require('./_auth');

const cognito = new CognitoIdentityProviderClient({ region: REGION });
const ddb = new DynamoDBClient({ region: REGION });
const TABLE_USERS              = process.env.TABLE_USERS               || 'Users';
const TABLE_VERIFICATION_CODES = process.env.TABLE_VERIFICATION_CODES  || 'VerificationCodes';
const TABLE_PARTNER_APPS       = process.env.TABLE_PARTNER_APPLICATIONS || 'PartnerApplications';
const TABLE_NOTIFICATIONS      = process.env.TABLE_NOTIFICATIONS        || 'Notifications';

async function findUsernameBySub(sub) {
  const page = await cognito.send(new ListUsersCommand({ UserPoolId: USER_POOL_ID, Filter: `sub = "${sub}"`, Limit: 1 }));
  return page.Users && page.Users[0] && page.Users[0].Username;
}

// Delete from a specific table (used for non-Users tables like VerificationCodes)
async function tryDeleteDdbRowInTable(table, key) {
  try {
    await ddb.send(new DeleteItemCommand({ TableName: table, Key: marshall(key) }));
    return true;
  } catch (err) {
    console.warn('[RentNivas] admin-delete-user: DynamoDB delete failed for table', table, 'key', JSON.stringify(key), '—', err.message || err);
    return false;
  }
}

// Attempt to delete a DynamoDB row — returns true on success, false on failure.
// DynamoDB DeleteItem returns success even when the item doesn't exist, so
// 'true' means "no unexpected error", not necessarily "something was deleted".
async function tryDeleteDdbRow(key) {
  try {
    await ddb.send(new DeleteItemCommand({ TableName: TABLE_USERS, Key: marshall(key) }));
    return true;
  } catch (err) {
    // Log real errors (IAM, throttle, schema mismatch) so they are visible in
    // CloudWatch / Vercel logs, but don't throw — cleanup is best-effort and
    // the Cognito user has already been deleted at this point.
    console.warn('[RentNivas] admin-delete-user: DynamoDB delete failed for key', JSON.stringify(key), '—', err.message || err);
    return false;
  }
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST' && req.method !== 'DELETE') return send(res, 405, { error: 'Method not allowed' });
  try {
    await requireAdmin(req);
    const body = await parseBody(req);
    const targetUserId = body.targetUserId || body.userId || body.id;
    let targetUsername = body.targetUsername || body.username || body.email;
    if (!targetUsername && targetUserId) {
      targetUsername = await findUsernameBySub(targetUserId);
    }
    if (!targetUserId && !targetUsername) throw new Error('targetUserId or targetUsername is required');
    if (!targetUsername) throw new Error('Cognito user not found for targetUserId');

    // ── Resolve sub + email from Cognito BEFORE deleting ──────────────────────
    // We need these values to clean up ALL related DynamoDB rows. Once the
    // Cognito user is deleted the attributes are gone, so we look them up first.
    let resolvedSub = targetUserId || null;
    let resolvedEmail = null;
    try {
      const userInfo = await cognito.send(new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: targetUsername
      }));
      const attrs = (userInfo.UserAttributes || []).reduce((acc, a) => { acc[a.Name] = a.Value; return acc; }, {});
      resolvedSub = attrs.sub || resolvedSub;
      resolvedEmail = (attrs.email || '').trim().toLowerCase() || null;
    } catch (lookupErr) {
      console.warn('[RentNivas] Could not pre-fetch Cognito attrs before deletion:', lookupErr.message || lookupErr);
    }

    // ── Delete Cognito user ────────────────────────────────────────────────────
    await cognito.send(new AdminDeleteUserCommand({ UserPoolId: USER_POOL_ID, Username: targetUsername }));

    // ── Delete ALL matching DynamoDB profile rows ──────────────────────────────
    // We attempt several key shapes because historical bugs created rows under
    // different partition key values for the same person:
    //   1. { userId: <cognito-sub> }   — the correct modern key
    //   2. { userId: <email> }         — ghost rows from the old email-as-key bug
    //   3. { id: <cognito-sub> }       — legacy rows from before the key rename
    //   4. { id: <email> }             — legacy ghost rows
    //
    // Using catch-all silent deletes (tryDeleteDdbRow) means a "miss" on a key
    // that was never created is harmless — DynamoDB DeleteItem is a no-op when
    // the key doesn't exist (it returns success, not an error).
    //
    // This guarantees that re-registering with the same email never finds
    // an orphaned row from the deleted account, regardless of how that row
    // was originally keyed.
    const cleanupResults = [];
    if (resolvedSub) {
      cleanupResults.push({ key: 'userId:sub', ok: await tryDeleteDdbRow({ userId: resolvedSub }) });
      cleanupResults.push({ key: 'id:sub',     ok: await tryDeleteDdbRow({ id: resolvedSub }) });
    }
    if (resolvedEmail) {
      cleanupResults.push({ key: 'userId:email', ok: await tryDeleteDdbRow({ userId: resolvedEmail }) });
      cleanupResults.push({ key: 'id:email',     ok: await tryDeleteDdbRow({ id: resolvedEmail }) });
    }
    // Also try with the raw targetUsername in case it differs from both above
    if (targetUsername && targetUsername !== resolvedSub && targetUsername !== resolvedEmail) {
      cleanupResults.push({ key: 'userId:username', ok: await tryDeleteDdbRow({ userId: targetUsername }) });
      cleanupResults.push({ key: 'id:username',     ok: await tryDeleteDdbRow({ id: targetUsername }) });
    }

    // ── Scan Users for any surviving ghost rows keyed by email ────────────────
    // DynamoDB DeleteItem with the wrong key shape is a silent no-op.
    // The { id: sub } variant above is useless because the PK is 'userId'.
    // Scan instead and nuke any row whose 'email' field matches — this catches
    // old email-keyed rows ({ userId: email }) or any other ghost key.
    // ALSO: grab the referral_code from any surviving row so we can find and
    // clear referred_by_code on everyone who used it (the core of the bug
    // where a re-registered user sees all old referrals as their own).
    const survivingReferralCodes = new Set();
    if (resolvedEmail || resolvedSub) {
      try {
        const scanRes = await ddb.send(new ScanCommand({ TableName: TABLE_USERS }));
        for (const raw of (scanRes.Items || [])) {
          const row = unmarshall(raw);
          const rowEmail = (row.email || '').trim().toLowerCase();
          const rowSub   = row.userId || row.id || '';
          const isMatch  = (resolvedEmail && rowEmail === resolvedEmail) ||
                           (resolvedSub   && rowSub   === resolvedSub);
          if (isMatch) {
            if (row.referral_code) survivingReferralCodes.add(String(row.referral_code));
            // Delete using whatever key the row actually has
            const key = row.userId ? { userId: row.userId } : { id: row.id };
            cleanupResults.push({ key: `scan:${JSON.stringify(key)}`, ok: await tryDeleteDdbRowInTable(TABLE_USERS, key) });
          }
        }
      } catch (e) {
        console.warn('[RentNivas] admin-delete-user: scan cleanup failed:', e.message);
      }
    }

    // ── Clear referred_by_code on users who were referred by the deleted account ──
    // Without this, anyone who has referred_by_code = deletedUser.referral_code
    // will appear in the re-registered user's referral history — making it look
    // like a fresh account instantly referred dozens of people.
    // We NULL out their referred_by_code so the history is clean.
    if (survivingReferralCodes.size > 0) {
      try {
        const scanRes2 = await ddb.send(new ScanCommand({ TableName: TABLE_USERS }));
        for (const raw of (scanRes2.Items || [])) {
          const row = unmarshall(raw);
          if (row.referred_by_code && survivingReferralCodes.has(String(row.referred_by_code))) {
            const key = row.userId ? { userId: row.userId } : { id: row.id };
            try {
              const pk = row.userId ? 'userId' : 'id';
              await ddb.send(new UpdateItemCommand({
                TableName: TABLE_USERS,
                Key: marshall(key),
                UpdateExpression: 'REMOVE referred_by_code',
                ConditionExpression: `attribute_exists(${pk})`
              }));
              console.log('[RentNivas] admin-delete-user: cleared referred_by_code on', row.userId || row.id);
            } catch (e2) {
              console.warn('[RentNivas] admin-delete-user: could not clear referred_by_code:', e2.message);
            }
          }
        }
      } catch (e) {
        console.warn('[RentNivas] admin-delete-user: referred_by_code clear scan failed:', e.message);
      }
    }

    // ── Delete VerificationCodes row (stores pendingReferralCode for email) ──
    // This is CRITICAL: if this row is not deleted, re-registration with the
    // same email will find the old pending referral code and stamp it on the
    // new account, causing the new user to inherit all referral history of
    // whoever was referred by that old code.
    if (resolvedEmail) {
      const vcPk = `signup_verify#${resolvedEmail}`;
      cleanupResults.push({
        key: 'VerificationCodes:email',
        ok: await tryDeleteDdbRowInTable(TABLE_VERIFICATION_CODES, { pk: vcPk })
      });
    }

    // ── Scan and delete all Notifications for this user ──
    // (best-effort; non-fatal if table doesn't exist or IAM is missing)
    if (resolvedSub) {
      try {
        const notifScan = await ddb.send(new ScanCommand({
          TableName: TABLE_NOTIFICATIONS,
          FilterExpression: 'userId = :uid',
          ExpressionAttributeValues: marshall({ ':uid': resolvedSub }),
          ProjectionExpression: 'id'
        }));
        for (const item of (notifScan.Items || [])) {
          const row = unmarshall(item);
          if (row.id) await tryDeleteDdbRowInTable(TABLE_NOTIFICATIONS, { id: row.id });
        }
      } catch (e) {
        console.warn('[RentNivas] admin-delete-user: notifications cleanup failed:', e.message);
      }
    }

    const anyCleanupFailed = cleanupResults.some(r => !r.ok);
    console.log('[RentNivas] admin-delete-user: deleted Cognito user and attempted DynamoDB cleanup for',
      resolvedEmail || targetUsername, '(sub:', resolvedSub, ') — cleanup results:', JSON.stringify(cleanupResults));

    send(res, 200, {
      ok: true,
      ddbCleanup: {
        attempted: cleanupResults.length,
        allSucceeded: !anyCleanupFailed,
        results: cleanupResults
      }
    });
  } catch (err) {
    console.error('[RentNivas] admin-delete-user failed:', err);
    send(res, /Admin access|required|authorization|token/i.test(err.message || '') ? 401 : 500, { error: err.message || 'Failed to delete user' });
  }
};
