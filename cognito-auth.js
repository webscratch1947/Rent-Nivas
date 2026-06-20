(function () {
  'use strict';

  var CONFIG = {
    region: 'eu-north-1',
    userPoolId: 'eu-north-1_GM7Zi2xvq',
    clientId: 'ckpmh0heco2apoh0temn8hfnl',
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
    var user = normalizeUser(decodeJwt(authResult.IdToken || authResult.AccessToken));
    var session = {
      access_token: authResult.AccessToken,
      id_token: authResult.IdToken,
      refresh_token: authResult.RefreshToken || prior.refresh_token,
      username: authResult.Username || prior.username || (user && user.email),
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

  async function refreshSession() {
    var current = getStoredSession();
    if (!current || !current.refresh_token) return { data: { session: null }, error: null };
    try {
      var data = await cognito('InitiateAuth', {
        AuthFlow: 'REFRESH_TOKEN_AUTH',
        ClientId: CONFIG.clientId,
        AuthParameters: { REFRESH_TOKEN: current.refresh_token, USERNAME: current.username }
      });
      var session = storeSession(Object.assign({}, data.AuthenticationResult, { RefreshToken: current.refresh_token, Username: current.username }));
      notify('TOKEN_REFRESHED', session);
      return { data: { session: session }, error: null };
    } catch (err) {
      log('session refresh failed', err);
      clearSession();
      notify('SIGNED_OUT', null);
      return { data: { session: null }, error: err };
    }
  }

  function scheduleRefresh(session) {
    if (refreshTimer) clearTimeout(refreshTimer);
    if (!session || !session.expires_at || !session.refresh_token) return;
    var ms = Math.max(30000, (session.expires_at * 1000) - Date.now() - 120000);
    refreshTimer = setTimeout(refreshSession, ms);
  }

  async function apiRequest(spec) {
    var sessionRes = await auth.getSession();
    var session = sessionRes.data.session;
    if (!session) return { data: null, error: { message: 'Not authenticated' } };
    var resp = await fetch('/api/data', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + session.access_token
      },
      body: JSON.stringify(spec)
    });
    var json = await resp.json().catch(function () { return { error: { message: 'Invalid API response' } }; });
    if (!resp.ok || json.error) return { data: null, error: json.error || { message: 'API request failed' }, count: json.count };
    return { data: json.data, error: null, count: json.count };
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
      try {
        var attrs = [{ Name: 'email', Value: payload.email }];
        var name = payload.options && payload.options.data && payload.options.data.name;
        if (name) attrs.push({ Name: 'name', Value: name });
        await cognito('SignUp', {
          ClientId: CONFIG.clientId,
          Username: payload.email,
          Password: payload.password,
          UserAttributes: attrs,
          ClientMetadata: {
            name: name || '',
            referral_code: (payload.options && payload.options.data && payload.options.data.referral_code) || ''
          }
        });
        sessionStorage.setItem('rn-pending-signup', JSON.stringify({
          email: payload.email,
          name: name || '',
          referral_code: (payload.options && payload.options.data && payload.options.data.referral_code) || ''
        }));
        return { data: { user: { email: payload.email }, session: null, confirmationRequired: true }, error: null };
      } catch (err) {
        log('signup failed', err, { email: payload && payload.email });
        return { data: { user: null, session: null }, error: err };
      }
    },

    async confirmSignUp(email, code) {
      try {
        await cognito('ConfirmSignUp', { ClientId: CONFIG.clientId, Username: email, ConfirmationCode: code });
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
        await cognito('ResendConfirmationCode', { ClientId: CONFIG.clientId, Username: email });
        return { data: {}, error: null };
      } catch (err) {
        log('verification resend failed', err, { email: email });
        return { data: null, error: err };
      }
    },

    async resetPasswordForEmail(email) {
      try {
        await cognito('ForgotPassword', { ClientId: CONFIG.clientId, Username: email });
        sessionStorage.setItem('rn-reset-email', email);
        return { data: {}, error: null };
      } catch (err) {
        log('forgot password failed', err, { email: email });
        return { data: null, error: err };
      }
    },

    async confirmForgotPassword(email, code, password) {
      try {
        await cognito('ConfirmForgotPassword', {
          ClientId: CONFIG.clientId,
          Username: email,
          ConfirmationCode: code,
          Password: password
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
      if (session.expires_at && session.expires_at * 1000 < Date.now() + 60000) return refreshSession();
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
    storage: {
      from: function (bucket) {
        async function storageRequest(payload) {
          var sessionRes = await auth.getSession();
          var session = sessionRes.data.session;
          if (!session) return { data: null, error: { message: 'Not authenticated' } };
          var resp = await fetch('/api/storage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + session.access_token },
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
})();
