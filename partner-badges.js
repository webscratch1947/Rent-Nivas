/* ════════════════════════════════════════════════════════════════
   RENT NIVAS — PARTNER BADGE / XP / TASK TIMER SYSTEM
   Load this AFTER the main inline <script> in index.html (it
   redefines a few functions on purpose to upgrade the old
   localStorage-only XP system to a DB-backed badge system).

   Requires partner task and XP data to be available through the
   Rent Nivas backend API, and the /badges/ folder (5 images) to be uploaded alongside
   index.html.
   ════════════════════════════════════════════════════════════════ */

(function () {

  // ── 5 BADGE TIERS ──────────────────────────────────────────────
  const BADGE_LEVELS = [
    { key: 'bronze',    name: 'Bronze',    short: 'Bronze',    minXp: 100,  img: 'badge-bronze.png',    emoji: '🥉' },
    { key: 'silver',    name: 'Silver',    short: 'Silver',    minXp: 300,  img: 'badge-silver.png',    emoji: '🥈' },
    { key: 'gold',      name: 'Gold',      short: 'Gold',      minXp: 600,  img: 'badge-gold.png',      emoji: '🥇' },
    { key: 'diamond',   name: 'Diamond',   short: 'Diamond',   minXp: 1000, img: 'badge-diamond.png',   emoji: '💎' },
    { key: 'legendary', name: 'Legendary', short: 'Legendary', minXp: 1500, img: 'badge-legendary.png', emoji: '🏆' },
  ];
  window.RN_BADGE_LEVELS = BADGE_LEVELS;

  function getBadgeInfo(xp) {
    xp = Math.max(0, Math.floor(xp || 0));
    let currentIdx = -1;
    for (let i = 0; i < BADGE_LEVELS.length; i++) {
      if (xp >= BADGE_LEVELS[i].minXp) currentIdx = i; else break;
    }
    const current = currentIdx >= 0 ? BADGE_LEVELS[currentIdx] : null;
    const next = (currentIdx + 1 < BADGE_LEVELS.length) ? BADGE_LEVELS[currentIdx + 1] : null;
    const lower = current ? current.minXp : 0;
    const upper = next ? next.minXp : (current ? current.minXp : 100);
    const span = Math.max(1, upper - lower);
    const into = Math.min(span, xp - lower);
    const pct = next ? Math.max(0, Math.min(100, (into / span) * 100)) : 100;
    return { xp, currentIdx, current, next, lower, upper, span, into, pct };
  }
  window.RN_getBadgeInfo = getBadgeInfo;

  // ── XP STATE (DB-backed, cached in memory) ─────────────────────
  window._partnerXP = window._partnerXP || 0;
  window._partnerXPLoaded = false;

  // getPartnerXP / setPartnerXP keep the same names the old code used
  // so existing call-sites keep working, but now they read/write the
  // DB-backed cache instead of a localStorage counter.
  window.getPartnerXP = function () { return window._partnerXP || 0; };
  window.setPartnerXP = function (v) {
    window._partnerXP = Math.max(0, Math.floor(v));
  };

  async function loadPartnerXPFromDB() {
    if (!user) return 0;
    try {
      const { data, error } = await sb.from('profiles').select('xp').eq('id', user.id).maybeSingle();
      if (!error && data) {
        window._partnerXP = Math.max(0, data.xp || 0);
        window._partnerXPLoaded = true;
      }
    } catch (e) { console.warn('[Nestly] loadPartnerXPFromDB error:', e.message || e); }
    return window._partnerXP || 0;
  }
  window.loadPartnerXPFromDB = loadPartnerXPFromDB;

  async function savePartnerXPToDB(newXp) {
    newXp = Math.max(0, Math.floor(newXp));
    window._partnerXP = newXp;
    if (!user) return;
    try {
      await sb.from('profiles').update({ xp: newXp }).eq('id', user.id);
    } catch (e) { console.warn('[Nestly] savePartnerXPToDB error:', e.message || e); }
  }
  window.savePartnerXPToDB = savePartnerXPToDB;

  // ── helper: minutes -> "1h 30m" / "45m" / "2d 3h" ──────────────
  window.fmtMinutes = function (mins) {
    mins = Math.max(0, Math.round(mins));
    const d = Math.floor(mins / 1440);
    const h = Math.floor((mins % 1440) / 60);
    const m = mins % 60;
    const parts = [];
    if (d) parts.push(d + 'd');
    if (h) parts.push(h + 'h');
    if (m && !d) parts.push(m + 'm');
    if (!parts.length) parts.push('0m');
    return parts.join(' ');
  };

  // ── RING + UI updates ───────────────────────────────────────────
  window.updateProfileBtnRing = function () {
    const ring = document.getElementById('pd-btn-ring');
    if (!ring) return;
    const info = getBadgeInfo(getPartnerXP());
    const circ = 2 * Math.PI * 17; // r=17
    const offset = circ * (1 - info.pct / 100);
    setTimeout(() => { ring.style.strokeDashoffset = offset; }, 200);

    const btnImg = document.getElementById('pd-btn-badge-img');
    if (btnImg) btnImg.src = info.current ? info.current.img : 'partner-badge.jpg';
    if (btnImg) btnImg.style.filter = 'none';
  };

  window.openPdProfile = function () {
    const sheet = document.getElementById('pd-profile-sheet');
    const panel = document.getElementById('pd-profile-panel');
    if (!sheet || !panel) return;
    sheet.style.display = 'block';
    setTimeout(() => { panel.style.transform = 'translateX(0)'; }, 20);

    // Render immediately with cached XP, then re-fetch from DB and re-render
    renderBadgeProfile();
    if (typeof loadPartnerXPFromDB === 'function') {
      loadPartnerXPFromDB().then(() => {
        updateProfileBtnRing();
        renderBadgeProfile();
      }).catch(() => {});
    }
  };

  window.closePdProfile = function () {
    const panel = document.getElementById('pd-profile-panel');
    const sheet = document.getElementById('pd-profile-sheet');
    if (panel) panel.style.transform = 'translateX(100%)';
    setTimeout(() => { if (sheet) sheet.style.display = 'none'; }, 380);
  };

  // Renders the badge image, name, rank, and animates the XP bar.
  // direction: 'up' | 'down' | null  — controls bar color + animation
  function renderBadgeProfile(direction) {
    const xp = getPartnerXP();
    const info = getBadgeInfo(xp);
    const done = getCompletedTaskCountCache();

    const imgEl = document.getElementById('pds-badge-img');
    const nameEl = document.getElementById('pds-badge-name');
    const levelEl = document.getElementById('pds-level-num');
    const nextEl = document.getElementById('pds-badge-next');
    const xpLabel = document.getElementById('pds-xp-label');
    const xpFraction = document.getElementById('pds-xp-fraction');
    const xpPct = document.getElementById('pds-xp-pct');
    const nextLabel = document.getElementById('pds-next-label');
    const milestoneSub = document.getElementById('pds-milestone-sub');
    const completedCount = document.getElementById('pds-completed-count');
    const totalXp = document.getElementById('pds-total-xp');
    const bar = document.getElementById('pds-xp-bar');
    const wrap = document.getElementById('pds-badge-wrap');

    if (imgEl) imgEl.src = info.current ? info.current.img : 'partner-badge.jpg';
    if (imgEl) imgEl.style.filter = 'none';
    if (nameEl) nameEl.textContent = info.current ? `${info.current.emoji} ${info.current.name}` : '🔒 Unranked';
    if (levelEl) levelEl.textContent = info.current ? (info.currentIdx + 1) + ' / 5' : '— / 5';

    if (nextEl) {
      if (info.next) {
        const remaining = Math.max(0, info.next.minXp - xp);
        nextEl.textContent = `Earn ${remaining} more XP to unlock ${info.next.name}`;
      } else {
        nextEl.textContent = '🏆 Top rank achieved — Diamond!';
      }
    }

    if (xpLabel) xpLabel.textContent = info.into + ' XP';
    if (xpFraction) xpFraction.textContent = info.into + ' / ' + info.span;
    if (xpPct) xpPct.textContent = Math.round(info.pct) + '%';
    if (completedCount) completedCount.textContent = done;
    if (totalXp) totalXp.textContent = xp;

    if (nextLabel) {
      nextLabel.textContent = info.next
        ? (info.next.minXp - xp) + ' XP to ' + info.next.name
        : '🎉 Max rank reached!';
    }
    if (milestoneSub) {
      milestoneSub.textContent = info.next
        ? 'Reach ' + info.next.minXp + ' total XP to unlock ' + info.next.name
        : 'You\'ve reached the highest badge — Diamond!';
    }

    // ── Animate the XP bar (grow on gain, shrink + red flash on loss) ──
    if (bar) {
      const lastXp = parseInt(localStorage.getItem('partner_xp_shown_' + (user?.id || '')) || '0', 10);
      const isUp = direction === 'up' || (direction == null && xp > lastXp);
      const isDown = direction === 'down' || (direction == null && xp < lastXp);
      localStorage.setItem('partner_xp_shown_' + (user?.id || ''), String(xp));

      bar.style.transition = 'none';
      // Start animation from previous percentage if known, else from current
      const startPct = (direction == null) ? info.pct : (parseFloat(bar.dataset.lastPct || info.pct));
      bar.style.width = (isDown ? Math.max(startPct, info.pct) : 0) + '%';

      if (isDown) {
        bar.style.background = 'linear-gradient(90deg,#ef4444,#b91c1c)';
        bar.style.boxShadow = '0 0 8px rgba(239,68,68,.6)';
      } else {
        bar.style.background = 'linear-gradient(90deg,#f59e0b,#ef4444,#ec4899)';
        bar.style.boxShadow = '0 0 8px rgba(245,158,11,.6)';
      }

      setTimeout(() => {
        bar.style.transition = 'width 1.6s cubic-bezier(.22,1,.36,1), background .6s ease';
        bar.style.width = info.pct + '%';
        bar.dataset.lastPct = info.pct;
        if (isUp && info.pct > 0) setTimeout(spawnXpParticles, 400);
        if (isDown) setTimeout(() => {
          bar.style.background = 'linear-gradient(90deg,#f59e0b,#ef4444,#ec4899)';
          bar.style.boxShadow = '0 0 8px rgba(245,158,11,.6)';
        }, 1700);
      }, 80);
    }

    // Badge "pop" animation when newly unlocked
    if (wrap && direction === 'badge-up') {
      wrap.style.transform = 'scale(1.18)';
      wrap.style.boxShadow = '0 8px 40px rgba(245,158,11,.7), 0 0 0 6px rgba(245,158,11,.25)';
      setTimeout(() => {
        wrap.style.transform = 'scale(1)';
        wrap.style.boxShadow = '0 8px 32px rgba(0,0,0,.4), 0 0 0 6px rgba(255,255,255,.07)';
      }, 700);
    }
  }
  window.renderBadgeProfile = renderBadgeProfile;

  window.spawnXpParticles = function () {
    const cel = document.getElementById('pd-xp-celebrate');
    if (!cel) return;
    cel.style.display = 'block';
    cel.innerHTML = '';
    const colors = ['#f59e0b', '#ef4444', '#10b981', '#3b82f6', '#a855f7', '#ec4899', '#fbbf24', '#34d399'];
    for (let i = 0; i < 50; i++) {
      const p = document.createElement('div');
      const sz = 6 + Math.random() * 9;
      p.style.cssText = `position:absolute;left:${5 + Math.random() * 90}%;top:-20px;width:${sz}px;height:${sz}px;
        border-radius:${Math.random() > .4 ? '50%' : '4px'};background:${colors[i % colors.length]};
        animation:xpDrop ${1 + Math.random() * .9}s ${Math.random() * .6}s ease-in forwards;`;
      cel.appendChild(p);
    }
    setTimeout(() => { cel.style.display = 'none'; cel.innerHTML = ''; }, 2600);
  };

  // ── BADGE UNLOCK / DOWNGRADE CELEBRATION OVERLAY ────────────────
  function ensureBadgePopup() {
    if (document.getElementById('rn-badge-popup')) return;
    const el = document.createElement('div');
    el.id = 'rn-badge-popup';
    el.style.cssText = 'position:fixed;inset:0;z-index:9300;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.65);backdrop-filter:blur(6px);padding:20px;';
    el.innerHTML = `
      <div style="background:linear-gradient(135deg,#7c2d12 0%,#b45309 50%,#d97706 100%);border-radius:24px;padding:32px 28px;max-width:340px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.12);">
        <div id="rn-bp-img-wrap" style="width:110px;height:110px;margin:0 auto 16px;border-radius:28px;background:rgba(255,255,255,.06);display:flex;align-items:center;justify-content:center;overflow:hidden;animation:rnBadgePop .6s cubic-bezier(.22,1,.36,1);">
          <img id="rn-bp-img" src="" alt="" style="width:84%;height:84%;object-fit:contain;">
        </div>
        <div id="rn-bp-title" style="font-size:20px;font-weight:900;color:#fff;margin-bottom:6px;"></div>
        <div id="rn-bp-sub" style="font-size:13px;color:rgba(255,255,255,.65);margin-bottom:20px;line-height:1.5;"></div>
        <button onclick="document.getElementById('rn-badge-popup').style.display='none'" style="background:#f59e0b;color:#1e1b4b;border:none;padding:11px 28px;border-radius:12px;font-size:14px;font-weight:800;cursor:pointer;">Awesome! 🎉</button>
      </div>
      <style>@keyframes rnBadgePop{0%{transform:scale(.4) rotate(-12deg);opacity:0;}60%{transform:scale(1.12) rotate(4deg);opacity:1;}100%{transform:scale(1) rotate(0);}}</style>
    `;
    document.body.appendChild(el);
  }

  function showBadgePopup(badge, isUpgrade) {
    ensureBadgePopup();
    const el = document.getElementById('rn-badge-popup');
    document.getElementById('rn-bp-img').src = badge.img;
    document.getElementById('rn-bp-title').textContent = isUpgrade
      ? `🎉 New Badge Unlocked!`
      : `Badge changed`;
    document.getElementById('rn-bp-sub').textContent = isUpgrade
      ? `You've reached ${badge.emoji} ${badge.name}! Keep completing tasks to climb higher.`
      : `Your rank is now ${badge.emoji} ${badge.name}.`;
    el.style.display = 'flex';
    if (isUpgrade) setTimeout(spawnXpParticles, 300);
  }

  // ── XP MUTATION HELPERS ──────────────────────────────────────────
  // Apply a delta to XP, persist, animate, and show a badge popup if the
  // badge tier changed.
  async function applyXPDelta(delta, opts) {
    opts = opts || {};
    const before = getPartnerXP();
    const beforeInfo = getBadgeInfo(before);
    const after = Math.max(0, before + delta);
    await savePartnerXPToDB(after);
    const afterInfo = getBadgeInfo(after);
    updateProfileBtnRing();

    const direction = delta > 0 ? 'up' : (delta < 0 ? 'down' : null);

    // Refresh profile sheet if open
    if (document.getElementById('pd-profile-sheet')?.style.display === 'block') {
      renderBadgeProfile(afterInfo.currentIdx !== beforeInfo.currentIdx ? 'badge-up' : direction);
    }

    if (afterInfo.currentIdx > beforeInfo.currentIdx && afterInfo.current) {
      showBadgePopup(afterInfo.current, true);
    } else if (afterInfo.currentIdx < beforeInfo.currentIdx) {
      if (afterInfo.current) showBadgePopup(afterInfo.current, false);
    }

    return { before, after, beforeInfo, afterInfo };
  }
  window.applyXPDelta = applyXPDelta;

  // ── COMPLETED TASKS CACHE (for the "TASKS DONE" stat) ────────────
  let _completedCount = 0;
  function getCompletedTaskCountCache() { return _completedCount; }

  // ── TASK LOADING / TIMER LOGIC ───────────────────────────────────
  const _taskTimers = []; // interval ids for live countdowns

  function clearTaskTimers() {
    _taskTimers.forEach(id => clearInterval(id));
    _taskTimers.length = 0;
  }

  window.loadPartnerDashboard = async function () {
    if (!user) { showPage('login-page'); return; }
    const name = user.user_metadata?.name || user.email?.split('@')[0] || 'Partner';
    const g = document.getElementById('pd-greeting');
    if (g) g.textContent = `Welcome, ${name} 🎉`;
    document.getElementById('role-host-btn')?.classList.remove('active');
    document.getElementById('role-rent-btn')?.classList.remove('active');
    await loadPartnerXPFromDB();
    updateProfileBtnRing();
    await loadPartnerTasks();
    // Always load referral stats immediately on dashboard open (Bug #9 fix)
    if (typeof loadPartnerReferralStats === 'function') loadPartnerReferralStats(false);
  };

  window.loadPartnerTasks = async function () {
    const el = document.getElementById('pd-tasks-list');
    const countEl = document.getElementById('pd-tasks-count');
    if (!el || !user) return;
    clearTaskTimers();

    try {
      const { data: tasks, error } = await sb.from('partner_tasks')
        .select('*').order('created_at', { ascending: false });
      if (error) throw error;

      const myTasks = (tasks || []).filter(t =>
        !t.assigned_to || t.assigned_to.includes(user.id) || t.assigned_to.includes(String(user.id))
      );

      // Load (or lazily create) progress rows for these tasks
      const progressMap = await ensureProgressRows(myTasks);

      // ── Apply any expirations (timer ran out without completion) ──
      await applyExpirations(myTasks, progressMap);

      // Count completed for stats
      _completedCount = [...progressMap.values()].filter(p => p.status === 'completed').length;

      // Visible = pending tasks only (completed/expired are hidden)
      const visible = myTasks.filter(t => {
        const p = progressMap.get(t.id);
        return !p || p.status === 'pending';
      });

      if (countEl) {
        countEl.style.display = visible.length ? 'inline-block' : 'none';
        countEl.textContent = visible.length;
      }

      if (!visible.length) {
        el.innerHTML = `<div style="text-align:center;padding:64px 20px;color:var(--muted);">
          <div style="font-size:48px;margin-bottom:14px;">🎉</div>
          <div style="font-size:16px;font-weight:700;color:var(--ink);margin-bottom:6px;">All caught up!</div>
          <div style="font-size:14px;">No pending tasks — check back later.</div>
        </div>`;
        return;
      }

      el.innerHTML = visible.map(t => renderPartnerTask(t, progressMap.get(t.id))).join('');

      // Start live countdowns
      visible.forEach(t => {
        const p = progressMap.get(t.id);
        if (p && p.deadline) startTaskCountdown(t.id, p.deadline);
      });

    } catch (e) {
      console.warn('[Nestly] loadPartnerTasks error:', e.message || e);
      el.innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted);">Could not load tasks.</div>';
    }
  };

  // Ensures every relevant task has a partner_task_progress row for this
  // user. Returns a Map(task_id -> progress row).
  async function ensureProgressRows(tasks) {
    const map = new Map();
    if (!tasks.length) return map;
    try {
      const ids = tasks.map(t => t.id);
      const { data, error } = await sb.from('partner_task_progress')
        .select('*').eq('user_id', user.id).in('task_id', ids);
      if (!error) (data || []).forEach(p => map.set(p.task_id, p));
    } catch (e) { console.warn('[Nestly] ensureProgressRows select error:', e.message || e); }

    // Create missing rows (lazy — covers "all partners" tasks created
    // before this partner was approved, or before this migration ran).
    const missing = tasks.filter(t => !map.has(t.id));
    if (missing.length) {
      const rows = missing.map(t => ({
        task_id: t.id,
        user_id: user.id,
        status: 'pending',
        deadline: t.time_limit_minutes ? new Date(Date.now() + t.time_limit_minutes * 60000).toISOString() : null
      }));
      try {
        const { data, error } = await sb.from('partner_task_progress').upsert(rows, { onConflict: 'task_id,user_id' }).select();
        if (!error) (data || []).forEach(p => map.set(p.task_id, p));
        else rows.forEach((r, i) => map.set(missing[i].id, r)); // optimistic fallback
      } catch (e) {
        rows.forEach((r, i) => map.set(missing[i].id, r));
      }
    }
    return map;
  }

  // Checks pending tasks with an expired deadline, applies the XP penalty,
  // marks them as 'expired'.
  async function applyExpirations(tasks, progressMap) {
    const now = Date.now();
    for (const t of tasks) {
      const p = progressMap.get(t.id);
      if (!p || p.status !== 'pending' || !p.deadline) continue;
      if (new Date(p.deadline).getTime() > now) continue;

      // Expired!
      const penalty = (t.xp_penalty != null ? t.xp_penalty : (t.xp_reward != null ? t.xp_reward : 10));
      p.status = 'expired';
      p.xp_penalty_taken = penalty;
      progressMap.set(t.id, p);

      try {
        await sb.from('partner_task_progress').update({
          status: 'expired', xp_penalty_taken: penalty
        }).eq('task_id', t.id).eq('user_id', user.id);
      } catch (e) { console.warn('[Nestly] mark expired error:', e.message || e); }

      // FIX: previously this only showed a one-time toast() popup. If the
      // user wasn't actively looking at the screen at the exact moment the
      // 30s timer tick (or this load) caught the expiry — which is the
      // common case, since tasks expire silently in the background — they
      // never saw it at all. The task just disappeared from the list with
      // no record anywhere of what happened to it or why their XP dropped.
      // Now it also goes into the persistent notification bell (pushNotif),
      // same system used for admin warnings/announcements, so it's there
      // whenever they next check, not just in the instant it happened.
      if (penalty > 0) {
        await applyXPDelta(-penalty);
        toast(`⏰ "${t.title}" expired — you lost ${penalty} XP`, 'error');
        if (typeof pushNotif === 'function') pushNotif('⏰', `Task "${t.title}" expired — you lost ${penalty} XP for not completing it in time.`);
      } else {
        toast(`⏰ "${t.title}" expired.`, 'error');
        if (typeof pushNotif === 'function') pushNotif('⏰', `Task "${t.title}" expired.`);
      }
    }
  }

  // Live countdown badge updater
  function startTaskCountdown(taskId, deadlineIso) {
    const elId = 'task-timer-' + taskId;
    const tick = () => {
      const el = document.getElementById(elId);
      if (!el) return; // task no longer rendered — stop silently
      const remainMs = new Date(deadlineIso).getTime() - Date.now();
      if (remainMs <= 0) {
        el.textContent = '⏰ Expired';
        el.style.color = '#ef4444';
        // Reload tasks shortly to apply the penalty + remove the card
        setTimeout(() => loadPartnerTasks(), 1200);
        return;
      }
      const mins = remainMs / 60000;
      el.textContent = '⏳ ' + fmtMinutes(mins) + ' left';
      el.style.color = mins < 60 ? '#ef4444' : (mins < 180 ? '#f59e0b' : 'var(--muted)');
    };
    tick();
    const id = setInterval(tick, 30000);
    _taskTimers.push(id);
  }

  // ── RENDER A TASK CARD (timer + xp aware) ────────────────────────
  window.renderPartnerTask = function (t, progress) {
    const TASK_LANGS = window.TASK_LANGS || [
      { code: 'en', label: '🇬🇧 English' }, { code: 'hi', label: '🇮🇳 Hindi' },
      { code: 'te', label: '🇮🇳 Telugu' }, { code: 'ta', label: '🇮🇳 Tamil' },
      { code: 'mr', label: '🇮🇳 Marathi' }, { code: 'bn', label: '🇮🇳 Bengali' },
      { code: 'gu', label: '🇮🇳 Gujarati' }, { code: 'kn', label: '🇮🇳 Kannada' },
      { code: 'ml', label: '🇮🇳 Malayalam' }, { code: 'pa', label: '🇮🇳 Punjabi' },
    ];
    const langOpts = TASK_LANGS.map(l => `<option value="${l.code}">${l.label}</option>`).join('');
    const hasLink = !!t.link;
    const titleJ = JSON.stringify(t.title).replace(/</g, '\\u003c');
    const descJ = JSON.stringify(t.description || '').replace(/</g, '\\u003c');
    const accents = ['#6366f1', '#f59e0b', '#10b981', '#ef4444', '#3b82f6', '#a855f7', '#ec4899'];
    const accent = accents[Math.abs(t.id.charCodeAt(0) + t.id.charCodeAt(1)) % accents.length];
    const xpReward = t.xp_reward != null ? t.xp_reward : 10;

    let timerHtml = '';
    if (t.time_limit_minutes && progress?.deadline) {
      timerHtml = `<span id="task-timer-${t.id}" style="font-size:11px;font-weight:800;color:var(--muted);white-space:nowrap;">⏳ ${fmtMinutes((new Date(progress.deadline).getTime() - Date.now()) / 60000)} left</span>`;
    }

    return `<div id="task-${t.id}" style="border-radius:20px;overflow:hidden;margin-bottom:16px;background:var(--bg);border:1.5px solid var(--border);box-shadow:0 2px 12px rgba(0,0,0,.06);transition:opacity .5s,transform .5s;">
      <!-- Color stripe -->
      <div style="height:5px;background:linear-gradient(90deg,${accent},${accent}aa);"></div>
      ${t.image_url ? `<img src="${esc(t.image_url)}" alt="" loading="lazy" style="width:100%;max-height:200px;object-fit:cover;">` : ''}
      <div style="padding:18px 20px;">
        <!-- Title row -->
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:8px;">
          <div class="task-title-el" style="font-size:16px;font-weight:800;color:var(--ink);line-height:1.3;flex:1;">${esc(t.title)}</div>
          <span style="flex-shrink:0;background:${accent}18;color:${accent};font-size:10px;font-weight:800;padding:3px 9px;border-radius:20px;letter-spacing:.4px;white-space:nowrap;border:1px solid ${accent}33;">+${xpReward} XP</span>
        </div>
        ${t.description ? `<div class="task-desc-el" style="font-size:13px;color:var(--muted);line-height:1.6;margin-bottom:12px;">${esc(t.description)}</div>` : ''}
        ${timerHtml ? `<div style="margin-bottom:12px;">${timerHtml}</div>` : ''}
        <!-- Link button — clicking auto-completes task -->
        ${hasLink ? `<a href="${esc(t.link)}" target="_blank" rel="noopener"
          onclick="setTimeout(()=>markTaskDone('${t.id}'),800)"
          style="display:inline-flex;align-items:center;gap:7px;background:var(--ink);color:#fff;padding:9px 16px;border-radius:12px;font-size:13px;font-weight:700;text-decoration:none;margin-bottom:14px;transition:opacity .15s;"
          onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
          🔗 Open Link <span style="opacity:.7;font-size:11px;">↗</span>
        </a>` : `<button onclick="markTaskDone('${t.id}')"
          style="display:inline-flex;align-items:center;gap:7px;background:${accent};color:#fff;border:none;padding:9px 16px;border-radius:12px;font-size:13px;font-weight:700;cursor:pointer;margin-bottom:14px;transition:opacity .15s;"
          onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
          ✅ Mark Complete
        </button>`}
        <!-- Footer: language + date -->
        <div style="display:flex;align-items:center;gap:8px;border-top:1px solid var(--border);padding-top:10px;flex-wrap:wrap;">
          <select onchange="translatePartnerTask('${t.id}',this.value,${titleJ},${descJ})"
            style="padding:5px 10px;border:1.5px solid var(--border2);border-radius:8px;font-size:12px;font-family:var(--font);background:var(--bg);color:var(--ink);cursor:pointer;flex:1;min-width:110px;">
            ${langOpts}
          </select>
          <span style="font-size:11px;color:var(--muted);">${t.created_at && !isNaN(new Date(t.created_at)) ? fmtDate(t.created_at) : ''}</span>
        </div>
        <div class="task-translating-${t.id}" style="display:none;font-size:12px;color:var(--muted);margin-top:6px;font-style:italic;">Translating...</div>
      </div>
    </div>`;
  };

  // ── MARK TASK DONE — now DB + XP/badge aware ─────────────────────
  window.markTaskDone = async function (taskId) {
    try {
      const { data: task } = await sb.from('partner_tasks').select('*').eq('id', taskId).maybeSingle();
      const xpReward = task?.xp_reward != null ? task.xp_reward : 10;

      await sb.from('partner_task_progress').update({
        status: 'completed', completed_at: new Date().toISOString(), xp_awarded: xpReward
      }).eq('task_id', taskId).eq('user_id', user.id);

      await applyXPDelta(xpReward);

      // Animate card out then reload
      const card = document.getElementById('task-' + taskId);
      if (card) {
        card.style.transition = 'opacity .5s ease, transform .5s ease, max-height .5s ease';
        card.style.opacity = '0';
        card.style.transform = 'scale(.95) translateY(-8px)';
        setTimeout(() => loadPartnerTasks(), 520);
      } else {
        loadPartnerTasks();
      }
      toast(`+${xpReward} XP earned! 🏆 Tap your profile to see progress.`, 'success');
    } catch (e) {
      console.warn('[Nestly] markTaskDone error:', e.message || e);
      toast('Could not mark task complete. Please try again.', 'error');
    }
  };

})();
