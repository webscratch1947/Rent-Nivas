(function () {
  'use strict';

  var CONFIG = {
    region:     (window.__RN_AWS_REGION              || 'eu-north-1'),
    userPoolId: (window.__RN_COGNITO_USER_POOL_ID    || 'eu-north-1_GM7Zi2xvq'),
    clientId:   (window.__RN_COGNITO_CLIENT_ID       || 'ckpmh0heco2apoh0temn8hfnl'),
    authFlow: 'USER_PASSWORD_AUTH',
    storageKey: 'rentnivas-auth'
  };

  var COGNITO_URL = 'https://cognito-idp.' + CONFIG.region + '.amazonaws.com/';
  var listeners = [];
  var refreshTimer = null;

  function log(scope, err, extra) {
    console.error('[RentNivas Cognito] ' + scope + ':', err, extra || '');
  }

  function friendlyError(err, fallback) {
    var msg = (err && (err.message || err.__type || err.code)) || fallback || 'Request failed.';
    if (/NotAuthorizedException/i.test(msg)) return 'Incorrect email or password.';
    if (/UserNotConfirmedException/i.test(msg)) return 'Please verify your email before signing in.';
    if (/UsernameExistsException/i.test(msg)) return 'An account with this email already exists.';
    if (/CodeMismatchException/i.test(msg)) return 'The verification code is incorrect.';
    if (/ExpiredCodeException/i.test(msg)) return 'The verification code has expired. Please request a new one.';
    if (/LimitExceededException|TooManyRequestsException/i.test(msg)) return 'Too many attempts. Please wait and try again.';
    if (/InvalidPasswordException/i.test(msg)) return 'Password does not meet the security requirements.';
    if (/UserNotFoundException/i.test(msg)) return 'No account exists for that email address.';
    return msg.replace(/^.*Exception:\s*/, '');
  }

  function decodeJwt(token) {
    if (!token) return null;
    try {
      var payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(decodeURIComponent(Array.prototype.map.call(atob(payload), function (c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join('')));
    } catch (err) {
      log('jwt decode failed', err);
      return null;
    }
  }

  function normalizeUser(payload) {
    if (!payload) return null;
    return {
      id: payload.sub,
      sub: payload.sub,
      email: payload.email,
      email_verified: payload.email_verified,
      user_metadata: {
        name: payload.name || payload.given_name || '',
        phone: payload.phone_number || '',
        referral_code: payload['custom:referral_code'] || null
      }
    };
  }

  function getStoredSession() {
    try {
      var raw = localStorage.getItem(CONFIG.storageKey);
      if (!raw) return null;
      var session = JSON.parse(raw);
      if (!session || !session.access_token) return null;
      session.user = session.user || normalizeUser(decodeJwt(session.id_token || session.access_token));
      return session;
    } catch (err) {
      log('session restore failed', err);
      return null;
    }
  }

  function storeSession(authResult) {
    var now = Math.floor(Date.now() / 1000);
    var prior = getStoredSession() || {};
    var tokenClaims = decodeJwt(authResult.AccessToken || authResult.IdToken);
    var user = normalizeUser(decodeJwt(authResult.IdToken || authResult.AccessToken));
    var resolvedUsername = authResult.Username
      || prior.username
      || (tokenClaims && (tokenClaims['cognito:username'] || tokenClaims.username || tokenClaims.email))
      || (user && user.email)
      || '';
    var session = {
      access_token: authResult.AccessToken,
      id_token: authResult.IdToken,
      refresh_token: authResult.RefreshToken || prior.refresh_token,
      username: resolvedUsername,
      token_type: authResult.TokenType || 'Bearer',
      expires_in: authResult.ExpiresIn || 3600,
      expires_at: now + (authResult.ExpiresIn || 3600),
      user: user
    };
    localStorage.setItem(CONFIG.storageKey, JSON.stringify(session));
    scheduleRefresh(session);
    return session;
  }

  function clearSession() {
    localStorage.removeItem(CONFIG.storageKey);
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = null;
  }

  function notify(event, session) {
    listeners.forEach(function (cb) {
      try { cb(event, session || null); } catch (err) { log('auth listener failed', err); }
    });
  }

  async function cognito(target, body) {
    var resp = await fetch('/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target, payload: body })
    });
    var json = await resp.json().catch(function () { return {}; });
    if (!resp.ok || json.error) {
      var errBody = json.error || json;
      var err = new Error(friendlyError(errBody, 'Cognito request failed.'));
      err.raw = errBody;
      throw err;
    }
    if (json.legacyAccount) {
      var legacyErr = new Error('LEGACY_ACCOUNT');
      legacyErr.legacyAccount = true;
      throw legacyErr;
    }
    return json.data;
  }

  // Custom backend endpoints (NOT Cognito) for password-reset and signup
  // email verification. These talk to /api/forgot-password and
  // /api/signup-verify, which generate their own codes, store them in
  // DynamoDB, and send them via Brevo SMTP — Cognito is only used afterwards
  // to actually set/confirm the account (AdminSetUserPassword /
  // AdminUpdateUserAttributes), not to send any email itself.
  async function customAuth(path, body) {
    var resp = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    var json = await resp.json().catch(function () { return {}; });
    if (!resp.ok || json.error) {
      var errMsg = (json.error && json.error.message) || (typeof json.error === 'string' ? json.error : 'Request failed.');
      var err = new Error(errMsg);
      err.raw = json.error;
      throw err;
    }
    return json.data;
  }

  // FIX: previously, ANY failure here (a one-off network blip, a slow
  // connection, Cognito briefly throttling, the tab waking up from being
  // backgrounded mid-request) immediately cleared the session and signed
  // the user out — permanently, with no retry. That is the cause of the
  // "auto logout after idle time" complaint: it usually wasn't really about
  // idle time at all, it was that the FIRST refresh attempt after any gap
  // happened to hit a transient hiccup and that one failure was treated as
  // "this user must be logged out".
  //
  // Fix: distinguish between
  //   (a) Cognito explicitly telling us the refresh token is invalid/expired
  //       (NotAuthorizedException) — this is a REAL logout, the session truly
  //       cannot be renewed, so we sign out.
  //   (b) anything else (network error, timeout, 5xx, throttling) — this is
  //       almost certainly transient, so we retry a few times with backoff
  //       before giving up, and even then we do NOT clear localStorage or
  //       sign the user out automatically — we just leave the existing
  //       (possibly stale) session in place and let the next natural retry
  //       (next user action, next visibility change) try again. The user
  //       is only ever actually signed out by an explicit, confirmed
  //       "this refresh token is no longer valid" response from Cognito.
  var REFRESH_RETRY_DELAYS_MS = [500, 1500];

  function isDefinitelyInvalidRefreshToken(err) {
    // NotAuthorizedException is Cognito's generic error code — it fires for
    // rate limits, transient failures, wrong clock, and other issues that are
    // NOT permanent token invalidation. Treating it as "sign out immediately"
    // causes users to be logged out after any background refresh hiccup.
    //
    // Only sign out when Cognito's message body *explicitly* says the refresh
    // token itself is the problem. All other errors are treated as transient.
    var msg = (err && (err.raw && (err.raw.__type || err.raw.message))) || (err && err.message) || '';
    return /Refresh Token has expired/i.test(msg)
        || /Invalid Refresh Token/i.test(msg)
        || /Token has been revoked/i.test(msg)
        || /Refresh token.*revoked/i.test(msg)
        || /UserNotFoundException/i.test(msg);
  }

  async function attemptRefresh(current) {
    var username = current.username;
    if (!username) {
      var claims = decodeJwt(current.access_token || current.id_token);
      username = (claims && (claims['cognito:username'] || claims.username || claims.email)) || '';
    }
    if (!username) throw new Error('Cannot refresh: username not found in stored session');
    return cognito('InitiateAuth', {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: CONFIG.clientId,
      AuthParameters: { REFRESH_TOKEN: current.refresh_token, USERNAME: username }
    });
  }

  function sleep(ms) { return new Promise(function (resolve) { setTimeout(resolve, ms); }); }

  var _refreshInFlight = null;
  async function refreshSession() {
    var current = getStoredSession();
    if (!current || !current.refresh_token) return { data: { session: null }, error: null };
    // De-dupe concurrent callers (multiple tabs/components asking for a
    // refresh at once) into a single in-flight attempt.
    if (_refreshInFlight) return _refreshInFlight;
    _refreshInFlight = (async function () {
      var lastErr = null;
      for (var attempt = 0; attempt <= REFRESH_RETRY_DELAYS_MS.length; attempt++) {
        try {
          var data = await attemptRefresh(current);
          var session = storeSession(Object.assign({}, data.AuthenticationResult, { RefreshToken: current.refresh_token, Username: current.username }));
          notify('TOKEN_REFRESHED', session);
          return { data: { session: session }, error: null };
        } catch (err) {
          lastErr = err;
          if (isDefinitelyInvalidRefreshToken(err)) {
            log('refresh token is genuinely invalid — signing out', err);
            clearSession();
            notify('SIGNED_OUT', null);
            return { data: { session: null }, error: err };
          }
          log('session refresh attempt ' + (attempt + 1) + ' failed (will retry if attempts remain)', err);
          if (attempt < REFRESH_RETRY_DELAYS_MS.length) {
            await sleep(REFRESH_RETRY_DELAYS_MS[attempt]);
          }
        }
      }
      // All retries exhausted on what looks like a transient issue.
      // Do NOT sign the user out — keep the existing session as-is so the
      // next natural opportunity (next action, next tab focus) can try
      // again. Re-arm the timer to try again shortly rather than giving up.
      log('session refresh exhausted retries (transient) — keeping session, will retry later', lastErr);
      refreshTimer = setTimeout(refreshSession, 30000);
      return { data: { session: current }, error: lastErr };
    })();
    try {
      return await _refreshInFlight;
    } finally {
      _refreshInFlight = null;
    }
  }

  function scheduleRefresh(session) {
    if (refreshTimer) clearTimeout(refreshTimer);
    if (!session || !session.expires_at || !session.refresh_token) return;
    // Refresh 5 minutes before expiry (increased from 2 min) to give more
    // buffer for background-tab timer throttling by browsers.
    var ms = (session.expires_at * 1000) - Date.now() - 300000;
    refreshTimer = setTimeout(refreshSession, Math.max(1, ms));
  }

  async function doFetch(token, spec) {
    var resp = await fetch('/api/data', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        // Use the ID token, not the Access Token — Cognito Access Tokens
        // never carry the `email` claim (only ID Tokens do), and the
        // backend's admin checks (ADMIN_EMAILS) read claims.email. Sending
        // the Access Token here meant claims.email was always undefined,
        // so admin checks could only ever pass via Cognito group membership,
        // never via ADMIN_EMAILS.
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify(spec)
    });
    var json = await resp.json().catch(function () { return { error: { message: 'Invalid API response' } }; });
    return { ok: resp.ok, json: json };
  }

  async function apiRequest(spec) {
    var sessionRes = await auth.getSession();
    var session = sessionRes.data.session;
    if (!session) return { data: null, error: { message: 'Not authenticated' } };

    // Pre-flight: if the stored token is already past its expiry time, force
    // a refresh now before even trying — avoids a guaranteed 401 round-trip.
    if (session.expires_at && session.expires_at * 1000 <= Date.now()) {
      var forced = await refreshSession();
      if (forced.data && forced.data.session) session = forced.data.session;
    }

    var token = session.id_token || session.access_token;
    var result = await doFetch(token, spec);

    // If the backend rejected with "Authorization token expired", force a
    // fresh token refresh and retry exactly once.  This handles the edge case
    // where the browser tab was backgrounded, the timer fired late, and an
    // expired token slipped through getSession's 5-minute guard.
    if (
      (!result.ok || result.json.error) &&
      result.json.error &&
      typeof result.json.error.message === 'string' &&
      result.json.error.message.toLowerCase().includes('token expired')
    ) {
      log('received token-expired error — forcing refresh and retrying once');
      var retry = await refreshSession();
      var retrySession = retry.data && retry.data.session;
      if (!retrySession) {
        // Refresh truly failed (e.g. refresh token revoked) — sign the user
        // out cleanly so they see the login screen instead of a broken app.
        clearSession();
        notify('SIGNED_OUT', null);
        return { data: null, error: { message: 'Your session has expired. Please sign in again.' } };
      }
      var retryToken = retrySession.id_token || retrySession.access_token;
      result = await doFetch(retryToken, spec);
    }

    if (!result.ok || result.json.error) return { data: null, error: result.json.error || { message: 'API request failed' }, count: result.json.count };
    return { data: result.json.data, error: null, count: result.json.count };
  }

  function Query(table) {
    this.spec = { table: table, op: 'select', select: '*', filters: [] };
  }
  Query.prototype.select = function (columns, opts) {
    if (!this.spec.op || this.spec.op === 'select') this.spec.op = 'select';
    this.spec.select = columns || '*';
    if (opts && opts.count) this.spec.count = opts.count;
    if (opts && opts.head) this.spec.head = true;
    return this;
  };
  Query.prototype.insert = function (values) { this.spec.op = 'insert'; this.spec.values = values; return this; };
  Query.prototype.upsert = function (values) { this.spec.op = 'upsert'; this.spec.values = values; return this; };
  Query.prototype.update = function (values) { this.spec.op = 'update'; this.spec.values = values; return this; };
  Query.prototype.delete = function () { this.spec.op = 'delete'; return this; };
  Query.prototype.eq = function (column, value) { this.spec.filters.push({ op: 'eq', column: column, value: value }); return this; };
  Query.prototype.in = function (column, values) { this.spec.filters.push({ op: 'in', column: column, values: values }); return this; };
  // FIX: .is() was called from index.html (ensureReferralCode's
  // `.is('referral_code', null)` guard) but was never implemented here.
  // Every call threw a synchronous TypeError ("...is is not a function"),
  // which silently aborted referral code generation for every user, every
  // time. Implemented to mirror Supabase's .is() (used for null/bool checks).
  Query.prototype.is = function (column, value) { this.spec.filters.push({ op: 'eq', column: column, value: value }); return this; };
  Query.prototype.or = function () { return this; };
  Query.prototype.order = function (column, opts) { this.spec.order = { column: column, ascending: !(opts && opts.ascending === false) }; return this; };
  Query.prototype.limit = function (n) { this.spec.limit = n; return this; };
  Query.prototype.single = function () { this.spec.single = true; return this; };
  Query.prototype.maybeSingle = function () { this.spec.maybeSingle = true; return this; };
  Query.prototype.catch = function (onRejected) { return this.then(null, onRejected); };
  Query.prototype.then = function (resolve, reject) { return apiRequest(this.spec).then(resolve, reject); };

  var auth = {
    async signInWithPassword(credentials) {
      try {
        var data = await cognito('InitiateAuth', {
          AuthFlow: CONFIG.authFlow,
          ClientId: CONFIG.clientId,
          AuthParameters: {
            USERNAME: credentials.email,
            PASSWORD: credentials.password
          }
        });
        var session = storeSession(data.AuthenticationResult);
        notify('SIGNED_IN', session);
        return { data: { session: session, user: session.user }, error: null };
      } catch (err) {
        log('login failed', err, { email: credentials && credentials.email });
        if (err.legacyAccount) err.message = 'LEGACY_ACCOUNT';
        return { data: { session: null, user: null }, error: err };
      }
    },

    async signUp(payload) {
      // NOTE: this no longer calls Cognito's public SignUp action (which would
      // make Cognito send its own confirmation email). Instead /api/signup-verify
      // creates the Cognito user server-side with MessageAction:'SUPPRESS',
      // sets the real password immediately, and sends a custom code via Brevo.
      try {
        var name = payload.options && payload.options.data && payload.options.data.name;
        var referralCode = (payload.options && payload.options.data && payload.options.data.referral_code) || '';
        await customAuth('/api/signup-verify', {
          action: 'request',
          email: payload.email,
          password: payload.password,
          name: name || '',
          referral_code: referralCode || ''
        });
        sessionStorage.setItem('rn-pending-signup', JSON.stringify({
          email: payload.email,
          name: name || '',
          referral_code: referralCode || ''
        }));
        return { data: { user: { email: payload.email }, session: null, confirmationRequired: true }, error: null };
      } catch (err) {
        log('signup failed', err, { email: payload && payload.email });
        return { data: { user: null, session: null }, error: err };
      }
    },

    async confirmSignUp(email, code) {
      try {
        await customAuth('/api/signup-verify', { action: 'confirm', email: email, code: code });
        var pending = {};
        try { pending = JSON.parse(sessionStorage.getItem('rn-pending-signup') || '{}'); } catch (_) {}
        sessionStorage.removeItem('rn-pending-signup');
        return { data: { email: email, profile: pending }, error: null };
      } catch (err) {
        log('email verification failed', err, { email: email });
        return { data: null, error: err };
      }
    },

    async resendConfirmationCode(email) {
      try {
        await customAuth('/api/signup-verify', { action: 'resend', email: email });
        return { data: {}, error: null };
      } catch (err) {
        log('verification resend failed', err, { email: email });
        return { data: null, error: err };
      }
    },

    async resetPasswordForEmail(email) {
      // Custom Brevo flow — see /api/forgot-password. Cognito's own
      // ForgotPassword action is no longer used, so this no longer relies on
      // (or is limited by) Cognito's built-in email sending.
      try {
        await customAuth('/api/forgot-password', { action: 'request', email: email });
        sessionStorage.setItem('rn-reset-email', email);
        return { data: {}, error: null };
      } catch (err) {
        log('forgot password failed', err, { email: email });
        return { data: null, error: err };
      }
    },

    async confirmForgotPassword(email, code, password) {
      try {
        await customAuth('/api/forgot-password', {
          action: 'confirm',
          email: email,
          code: code,
          newPassword: password
        });
        return { data: {}, error: null };
      } catch (err) {
        log('password reset confirmation failed', err, { email: email });
        return { data: null, error: err };
      }
    },

    async updateUser(attrs) {
      if (attrs && attrs.password) {
        return { data: null, error: new Error('Use the Cognito password reset code flow to change forgotten passwords.') };
      }
      return { data: { user: (getStoredSession() || {}).user || null }, error: null };
    },

    async getSession() {
      var session = getStoredSession();
      if (!session) return { data: { session: null }, error: null };
      // Refresh if within 5 minutes of expiry (matches scheduleRefresh buffer)
      if (session.expires_at && session.expires_at * 1000 < Date.now() + 300000) return refreshSession();
      scheduleRefresh(session);
      return { data: { session: session }, error: null };
    },

    async getUser() {
      var session = (await this.getSession()).data.session;
      return { data: { user: session ? session.user : null }, error: null };
    },

    async signOut() {
      clearSession();
      notify('SIGNED_OUT', null);
      return { data: null, error: null };
    },

    async setSession(tokens) {
      var session = storeSession({
        AccessToken: tokens.access_token,
        IdToken: tokens.id_token || tokens.access_token,
        RefreshToken: tokens.refresh_token,
        ExpiresIn: tokens.expires_in || 3600,
        TokenType: 'Bearer'
      });
      notify('SIGNED_IN', session);
      return { data: { session: session, user: session.user }, error: null };
    },

    onAuthStateChange(callback) {
      listeners.push(callback);
      return { data: { subscription: { unsubscribe: function () {
        listeners = listeners.filter(function (cb) { return cb !== callback; });
      } } } };
    }
  };

  window.RentNivasAuth = { config: CONFIG, auth: auth, apiRequest: apiRequest, decodeJwt: decodeJwt };
  window.sb = {
    auth: auth,
    from: function (table) { return new Query(table); },
    rpc: function (name, params) { return apiRequest({ op: 'rpc', name: name, params: params || {} }); },
    // Realtime channels are not supported on this backend — stubs prevent TypeErrors
    channel: function () { return { on: function () { return this; }, subscribe: function () { return this; } }; },
    removeChannel: function () {},
    storage: {
      from: function (bucket) {
        async function storageRequest(payload) {
          var sessionRes = await auth.getSession();
          var session = sessionRes.data.session;
          if (!session) return { data: null, error: { message: 'Not authenticated' } };
          var resp = await fetch('/api/storage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (session.id_token || session.access_token) },
            body: JSON.stringify(Object.assign({ bucket: bucket }, payload))
          });
          var json = await resp.json().catch(function () { return { error: { message: 'Invalid storage response' } }; });
          if (!resp.ok || json.error) return { data: null, error: json.error || { message: 'Storage request failed' } };
          return { data: json.data, error: null };
        }
        function fileToDataUrl(file) {
          return new Promise(function (resolve, reject) {
            var reader = new FileReader();
            reader.onload = function () { resolve(reader.result); };
            reader.onerror = function () { reject(reader.error || new Error('Could not read file')); };
            reader.readAsDataURL(file);
          });
        }
        return {
          upload: async function (path, file, options) {
            try {
              return await storageRequest({ op: 'upload', path: path, file: await fileToDataUrl(file), contentType: file.type, cacheControl: options && options.cacheControl });
            } catch (err) {
              console.error('[RentNivas] storage upload failed:', err);
              return { data: null, error: { message: err.message || 'Upload failed' } };
            }
          },
          remove: async function (paths) { return storageRequest({ op: 'remove', paths: paths || [] }); },
          list: async function (prefix) { return storageRequest({ op: 'list', prefix: prefix || '' }); },
          download: async function () { return { data: null, error: { message: 'Use public URLs for Rent Nivas image downloads.' } }; },
          getPublicUrl: function (path) {
            var base = window.__RN_S3_PUBLIC_BASE_URL || '';
            return { data: { publicUrl: base ? base.replace(/\/$/, '') + '/' + encodeURI(path) : path } };
          }
        };
      }
    }
  };

  var restored = getStoredSession();
  if (restored) scheduleRefresh(restored);

  // When the tab comes back to the foreground after being in the background,
  // browsers may have throttled or silently dropped the refresh setTimeout.
  // This listener fires immediately on visibility restore and proactively
  // refreshes the token if it has already expired or is within 5 minutes of
  // expiry — preventing the "logged out after leaving tab in background" bug.
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState !== 'visible') return;
    var session = getStoredSession();
    if (!session || !session.refresh_token) return;
    var expiresAt = session.expires_at ? session.expires_at * 1000 : 0;
    if (expiresAt < Date.now() + 300000) {
      refreshSession();
    }
  });
})();
