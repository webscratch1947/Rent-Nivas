/* ══ RentNivas cache buster ══
   Loads on every page. Polls /api/env-inject.js?json=1 (never edge-cached,
   already used by every page anyway) for the current site version. If this
   device's stored version doesn't match, it wipes Cache Storage / Service
   Workers and force-reloads with a cache-busting query param.
   Works for brand-new visitors AND returning users — no login required. */
(function () {
  var ENDPOINT = '/api/env-inject.js?json=1';
  var KEY = 'rn_site_version';
  var CHECK_INTERVAL_MS = 5 * 60 * 1000; // re-check every 5 minutes while the tab is open

  function wipeAndReload(newVersion) {
    try { localStorage.setItem(KEY, String(newVersion)); } catch (e) {}
    var done = function () {
      var url = window.location.pathname +
        (window.location.search ? window.location.search + '&' : '?') +
        '_rnv=' + Date.now();
      window.location.replace(url);
    };
    var tasks = [];
    if (window.caches && caches.keys) {
      tasks.push(caches.keys().then(function (names) {
        return Promise.all(names.map(function (n) { return caches.delete(n); }));
      }).catch(function () {}));
    }
    if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {
      tasks.push(navigator.serviceWorker.getRegistrations().then(function (regs) {
        return Promise.all(regs.map(function (r) { return r.unregister(); }));
      }).catch(function () {}));
    }
    Promise.all(tasks).then(done).catch(done);
  }

  function checkVersion() {
    fetch(ENDPOINT, { cache: 'no-store', headers: { 'pragma': 'no-cache' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) {
        if (!data || !data.version) return;
        var stored = null;
        try { stored = localStorage.getItem(KEY); } catch (e) {}
        if (stored === null) {
          // First time we've seen this device — just remember the version.
          try { localStorage.setItem(KEY, String(data.version)); } catch (e) {}
          return;
        }
        if (String(data.version) !== String(stored)) {
          wipeAndReload(data.version);
        }
      })
      .catch(function () {});
  }

  checkVersion();
  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') checkVersion();
  });
  window.addEventListener('focus', checkVersion);
  setInterval(checkVersion, CHECK_INTERVAL_MS);
})();
