const { DynamoDBClient, PutItemCommand, GetItemCommand, ScanCommand, UpdateItemCommand } = require('@aws-sdk/client-dynamodb');
const { marshall, unmarshall } = require('@aws-sdk/util-dynamodb');
const { send, parseBody, verifyToken, isAdmin } = require('./_auth');

// ── Main AWS (for reading user profiles: name, avatar_url, credits) ──
const MAIN_REGION = process.env.AWS_REGION || process.env.RENT_NIVAS_AWS_REGION || 'eu-north-1';
const mainDdb = new DynamoDBClient({ region: MAIN_REGION });
const TABLE_USERS = process.env.TABLE_USERS || 'Users';

// ── Broker AWS (separate credentials) ──
const BROKER_REGION = process.env.BROKER_AWS_REGION || MAIN_REGION;
const brokerDdb = new DynamoDBClient({
  region: BROKER_REGION,
  credentials: {
    accessKeyId: process.env.BROKER_AWS_KEY || '',
    secretAccessKey: process.env.BROKER_AWS_SECRET || '',
  },
});

const TABLE_BROKER_POSTS = 'BrokerPosts';
const TABLE_BROKER_PROFILES = 'BrokerProfiles';
const TABLE_BROKER_CONNECTIONS = 'BrokerConnections';

// ── Helpers ──

async function getMainUserProfile(userId) {
  try {
    const res = await mainDdb.send(new GetItemCommand({
      TableName: TABLE_USERS,
      Key: marshall({ userId }),
      ProjectionExpression: 'userId, #n, avatar_url, email',
      ExpressionAttributeNames: { '#n': 'name' },
    }));
    if (!res.Item) return null;
    const item = unmarshall(res.Item);
    return { id: item.userId, name: item.name || 'User', avatar_url: item.avatar_url || '', email: item.email || '' };
  } catch (err) {
    console.error('[Broker] Failed to fetch user profile:', userId, err.message);
    return null;
  }
}

async function getUserCredits(userId) {
  try {
    const res = await mainDdb.send(new GetItemCommand({
      TableName: TABLE_USERS,
      Key: marshall({ userId }),
      ProjectionExpression: 'credits',
    }));
    if (!res.Item) return 0;
    const item = unmarshall(res.Item);
    return parseFloat(item.credits) || 0;
  } catch (err) {
    console.error('[Broker] Failed to fetch credits:', userId, err.message);
    return 0;
  }
}

async function setUserCredits(userId, newCredits) {
  try {
    await mainDdb.send(new UpdateItemCommand({
      TableName: TABLE_USERS,
      Key: marshall({ userId }),
      UpdateExpression: 'SET credits = :c',
      ExpressionAttributeValues: marshall({ ':c': newCredits }),
    }));
  } catch (err) {
    console.error('[Broker] Failed to set credits:', userId, err.message);
  }
}

async function getBrokerProfile(userId) {
  try {
    const res = await brokerDdb.send(new GetItemCommand({
      TableName: TABLE_BROKER_PROFILES,
      Key: marshall({ userId }),
    }));
    if (!res.Item) return { userId, isBroker: false, isVerified: false };
    const item = unmarshall(res.Item);
    return { userId: item.userId, isBroker: !!item.isBroker, isVerified: !!item.isVerified };
  } catch (err) {
    console.error('[Broker] Failed to get broker profile:', userId, err.message);
    return { userId, isBroker: false, isVerified: false };
  }
}

// ── Handlers ──

async function handleGetFeed() {
  // Scan all posts (newest first)
  const res = await brokerDdb.send(new ScanCommand({ TableName: TABLE_BROKER_POSTS }));
  const posts = (res.Items || []).map(unmarshall).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

  // Enrich with user profiles from main DB
  const enriched = await Promise.all(posts.map(async (post) => {
    const profile = await getMainUserProfile(post.userId);
    return {
      ...post,
      userName: profile?.name || post.userName || 'User',
      avatarUrl: profile?.avatar_url || '',
    };
  }));

  return enriched;
}

async function handleCreatePost(claims, body) {
  const userId = claims.sub;
  const postId = 'bp-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
  const now = Date.now();

  const item = {
    postId,
    type: body.type || 'need',
    propertyType: body.propertyType || '',
    purpose: body.purpose || '',
    listingType: body.listingType || '',
    budget: body.budget || '',
    price: body.price || '',
    location: body.location || '',
    extra: body.extra || '',
    userId,
    createdAt: now,
  };

  await brokerDdb.send(new PutItemCommand({
    TableName: TABLE_BROKER_POSTS,
    Item: marshall(item, { removeUndefinedValues: true }),
  }));

  // Fetch profile to return enriched post
  const profile = await getMainUserProfile(userId);
  const brokerProf = await getBrokerProfile(userId);

  return {
    ...item,
    userName: profile?.name || 'User',
    avatarUrl: profile?.avatar_url || '',
    verified: brokerProf.isVerified,
  };
}

async function handleConnect(claims, body) {
  const userId = claims.sub;
  const postId = body.postId;
  if (!postId) throw new Error('Missing postId');

  // Get the post to find the target userId
  const postRes = await brokerDdb.send(new GetItemCommand({
    TableName: TABLE_BROKER_POSTS,
    Key: marshall({ postId }),
  }));
  if (!postRes.Item) throw new Error('Post not found');
  const post = unmarshall(postRes.Item);

  if (post.userId === userId) throw new Error('Cannot connect with yourself');

  // Check if already connected
  const existingConn = await brokerDdb.send(new ScanCommand({
    TableName: TABLE_BROKER_CONNECTIONS,
    FilterExpression: 'userId = :uid AND postId = :pid',
    ExpressionAttributeValues: marshall({ ':uid': userId, ':pid': postId }),
  }));
  if (existingConn.Items && existingConn.Items.length > 0) {
    throw new Error('Already connected with this post');
  }

  // Check and deduct credits
  const credits = await getUserCredits(userId);
  if (credits < 10) throw new Error('Not enough credits. You need 10 credits to connect.');

  await setUserCredits(userId, credits - 10);

  // Create connection record
  const connectionId = 'conn-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
  await brokerDdb.send(new PutItemCommand({
    TableName: TABLE_BROKER_CONNECTIONS,
    Item: marshall({
      connectionId,
      userId,
      targetUserId: post.userId,
      postId,
      coinsSpent: 10,
      createdAt: new Date().toISOString(),
    }),
  }));

  // Get target's profile from main DB
  const targetProfile = await getMainUserProfile(post.userId);

  return {
    connectionId,
    targetEmail: targetProfile?.email || '',
    targetName: targetProfile?.name || 'User',
    remainingCredits: credits - 10,
  };
}

async function handleGetProfile(claims) {
  const userId = claims.sub;
  const brokerProf = await getBrokerProfile(userId);
  const credits = await getUserCredits(userId);
  return { ...brokerProf, credits };
}

async function handleToggleRole(claims, body) {
  const userId = body.userId || claims.sub;
  const current = await getBrokerProfile(userId);
  const newVal = !current.isBroker;

  await brokerDdb.send(new PutItemCommand({
    TableName: TABLE_BROKER_PROFILES,
    Item: marshall({
      userId,
      isBroker: newVal,
      isVerified: current.isVerified,
      updatedAt: new Date().toISOString(),
    }),
  }));

  return { userId, isBroker: newVal, isVerified: current.isVerified };
}

async function handleToggleVerified(claims, body) {
  const userId = body.userId;
  if (!userId) throw new Error('Missing userId');
  const current = await getBrokerProfile(userId);
  const newVal = !current.isVerified;

  await brokerDdb.send(new PutItemCommand({
    TableName: TABLE_BROKER_PROFILES,
    Item: marshall({
      userId,
      isBroker: current.isBroker,
      isVerified: newVal,
      verifiedAt: newVal ? new Date().toISOString() : null,
      updatedAt: new Date().toISOString(),
    }),
  }));

  return { userId, isBroker: current.isBroker, isVerified: newVal };
}

async function handleAdminGetPosts() {
  const res = await brokerDdb.send(new ScanCommand({ TableName: TABLE_BROKER_POSTS }));
  const posts = (res.Items || []).map(unmarshall).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

  const enriched = await Promise.all(posts.slice(0, 50).map(async (post) => {
    const profile = await getMainUserProfile(post.userId);
    const brokerProf = await getBrokerProfile(post.userId);
    return {
      ...post,
      userName: profile?.name || 'User',
      avatarUrl: profile?.avatar_url || '',
      verified: brokerProf.isVerified,
    };
  }));

  return enriched;
}

// ── Main handler ──

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (req.method !== 'POST' && req.method !== 'GET') return send(res, 405, { error: 'Method not allowed' });

  try {
    const claims = await verifyToken(req);

    // GET requests
    if (req.method === 'GET') {
      const url = new URL(req.url, 'http://localhost');
      const action = url.searchParams.get('action');

      if (action === 'feed') {
        const data = await handleGetFeed();
        return send(res, 200, { data, error: null });
      }
      if (action === 'profile') {
        const data = await handleGetProfile(claims);
        return send(res, 200, { data, error: null });
      }
      return send(res, 400, { error: 'Unknown action' });
    }

    // POST requests
    const body = await parseBody(req);
    const action = body.action;

    if (action === 'create-post') {
      const data = await handleCreatePost(claims, body);
      return send(res, 200, { data, error: null });
    }
    if (action === 'connect') {
      const data = await handleConnect(claims, body);
      return send(res, 200, { data, error: null });
    }
    if (action === 'toggle-role') {
      const claims2 = await verifyToken(req);
      const adminCheck = isAdmin(claims2);
      if (!adminCheck) {
        const myProf = await getBrokerProfile(claims2.sub);
        if (!myProf.isBroker) throw new Error('Admin or broker access required');
      }
      const data = await handleToggleRole(claims, body);
      return send(res, 200, { data, error: null });
    }
    if (action === 'toggle-verified') {
      if (!isAdmin(claims)) throw new Error('Admin access required');
      const data = await handleToggleVerified(claims, body);
      return send(res, 200, { data, error: null });
    }
    if (action === 'admin-posts') {
      if (!isAdmin(claims)) throw new Error('Admin access required');
      const data = await handleAdminGetPosts();
      return send(res, 200, { data, error: null });
    }

    return send(res, 400, { error: 'Unknown action: ' + action });
  } catch (err) {
    console.error('[Broker API] Error:', err);
    send(res, err.message && err.message.includes('authorization') ? 401 : 400, {
      data: null,
      error: { message: err.message || 'Request failed' },
    });
  }
};
