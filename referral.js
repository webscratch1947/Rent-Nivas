/**
 * referral.js  –  Rent Nivas referral system v2
 *
 * Drop this file in your project root and add ONE line to the bottom of
 * index.html (just before </body>):
 *
 *   <script src="/referral.js"></script>
 *
 * This file overrides two functions that still query the old Users table:
 *
 *   rnrefLoadData()      — now calls the new get_referral_data RPC which
 *                          reads from the Referrals table directly.
 *
 *   _doReferralLookup()  — now calls /api/check-referral (the same public
 *                          endpoint already used by the signup form) instead
 *                          of querying sb.from('profiles') for referral_code.
 *
 * Every other referral function (ensureReferralCode, processPendingSignupReferral,
 * openReferralPanel, rnrefRenderList, rnrefSwitchTab, etc.) needs NO changes
 * because their logic is unchanged — only the server-side RPC implementation
 * changed, and that is handled by the updated api/data.js.
 */

(function () {
  'use strict';

  // ── rnrefLoadData ─────────────────────────────────────────────────────────
  // Replaces the old version that called sb.from('profiles') + sb.from('houses').
  // Now calls a single get_referral_data RPC that reads from the Referrals table.
  //
  // Return shape from the RPC:
  //   { referralCode, active, totalReferrals, registrationReferrals,
  //     listingReferrals,
  //     referredUsers:    [{ userId, name, email, avatar, joinedAt }],
  //     referredListings: [{ listingId, title, image, ownerId, ownerName, listedAt }] }
  //
  window.rnrefLoadData = async function rnrefLoadData() {
    if (!window.user) return;

    var listEl = document.getElementById('rnref-hist-list');
    if (listEl) listEl.innerHTML = '<div class="rnref-empty">Loading...</div>';

    try {
      // ── 1. Ensure the user has a referral code (creates Referrals row too) ──
      var ensured = await sb.rpc('get_or_create_referral_code', {});
      var codeFromEnsure = ensured && ensured.data && ensured.data.referral_code;

      // ── 2. Pull full referral history from the Referrals table ────────────
      var rpcRes = await sb.rpc('get_referral_data', {});
      var rd     = (rpcRes && rpcRes.data) || {};

      var referralCode          = rd.referralCode           || codeFromEnsure || '';
      var totalReferrals        = parseInt(rd.totalReferrals        || 0, 10);
      var registrationReferrals = parseInt(rd.registrationReferrals || 0, 10);
      var listingReferrals      = parseInt(rd.listingReferrals      || 0, 10);
      var referredUsers         = Array.isArray(rd.referredUsers)    ? rd.referredUsers    : [];
      var referredListings      = Array.isArray(rd.referredListings) ? rd.referredListings : [];

      // Update the global code used by copyCode / invite helpers
      window._rnrefCode = referralCode;

      // Update the hero code display
      var codeValEl = document.getElementById('rnref-code-val');
      if (codeValEl) codeValEl.textContent = referralCode || '————';

      // ── 3. Determine partner status for reward label ──────────────────────
      var isPartner  = false;
      try {
        isPartner = !!(window._pdIsPartner && (await window._pdIsPartner(window.user.id)));
      } catch (e) { /* non-fatal */ }
      var rewardLabel = isPartner ? '+5 XP · +0.50 Credit' : '+0.50 Credit';

      // ── 4. Map API data → _rnrefData format expected by rnrefRenderList ───
      window._rnrefData = window._rnrefData || {};

      window._rnrefData.register = referredUsers.map(function (u) {
        return {
          name:   u.name   || 'Unknown user',
          email:  u.email  || '',
          avatar: u.avatar || '',
          date:   u.joinedAt || '',
          reward: rewardLabel,
        };
      });

      window._rnrefData.house = referredListings.map(function (l) {
        return {
          name:      l.title     || 'Untitled property',
          id:        l.listingId || '',
          image:     l.image     || '',
          publisher: l.ownerName || 'Unknown user',
          date:      l.listedAt  || '',
          reward:    rewardLabel,
        };
      });

      // ── 5. Show success popup if new referral detected since last visit ───
      try {
        var totalRefs     = totalReferrals;
        var storageKey    = 'rn-last-ref-total-' + window.user.id;
        var popupShownKey = 'rn-ref-popup-shown-'  + window.user.id;
        var lastKnown     = parseInt(localStorage.getItem(storageKey)    || '-1', 10);
        var popupShown    = localStorage.getItem(popupShownKey);
        if (totalRefs > 0 && !popupShown) {
          window.rnrefShowSuccessPopup && window.rnrefShowSuccessPopup();
          localStorage.setItem(popupShownKey, '1');
        } else if (lastKnown !== -1 && totalRefs > lastKnown) {
          window.rnrefShowSuccessPopup && window.rnrefShowSuccessPopup();
        }
        localStorage.setItem(storageKey, totalRefs);
      } catch (e) { /* non-fatal */ }

      // ── 6. Render ─────────────────────────────────────────────────────────
      window.rnrefRenderList && window.rnrefRenderList();
      window.rnrefRenderFaq  && window.rnrefRenderFaq();

    } catch (e) {
      console.warn('[Referral v2] rnrefLoadData error:', e && e.message);
      if (listEl) listEl.innerHTML = '<div class="rnref-empty">Could not load referral data.</div>';
    }
  };


  // ── _doReferralLookup ─────────────────────────────────────────────────────
  // Replaces the old version that used sb.from('profiles').eq('referral_code').
  // Now calls /api/check-referral — same public, unauthenticated endpoint
  // already used by the signup form (_doSignupRefLookup).
  //
  // This fixes the Add Listing form: the old code did an authenticated query
  // to the Users table for a referral_code field that no longer drives the
  // lookup in the new Referrals table schema.
  //
  window._doReferralLookup = async function _doReferralLookup(code) {
    var resultEl = document.getElementById('referral-result');
    var errorEl  = document.getElementById('referral-error');
    var nameEl   = document.getElementById('referral-result-name');
    var emailEl  = document.getElementById('referral-result-email');

    if (resultEl) resultEl.style.display = 'none';
    if (errorEl)  errorEl.style.display  = 'none';

    if (!code || code.length < 4) return;

    try {
      var resp = await fetch('/api/check-referral', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ code: code }),
      });
      var json = await resp.json().catch(function () { return {}; });
      var data = json && json.data;

      if (!resp.ok || !data) {
        if (errorEl) {
          errorEl.textContent = '❌ Invalid referral code. Please check and try again.';
          errorEl.style.display = 'block';
        }
        return;
      }

      // Self-referral guard (same check as before)
      if (window.user && window.user.referral_code && code.toUpperCase() === String(window.user.referral_code).toUpperCase()) {
        if (errorEl) {
          errorEl.textContent = "❌ That's your own referral code — enter someone else's instead.";
          errorEl.style.display = 'block';
        }
        return;
      }

      if (nameEl)  nameEl.textContent  = data.name  || (data.email ? data.email.split('@')[0] : 'Rent Nivas user');
      if (emailEl) emailEl.textContent = data.email || '—';
      if (resultEl) resultEl.style.display = 'block';

    } catch (e) {
      if (errorEl) {
        errorEl.textContent = '❌ Invalid referral code. Please check and try again.';
        errorEl.style.display = 'block';
      }
    }
  };

  console.log('[Referral v2] referral.js loaded — rnrefLoadData + _doReferralLookup overridden');

})();
