/* ============================================================
   Chase Park Church of Christ — Main JS
   Mobile nav · Active nav state · Scroll reveal · Sermons
   ============================================================ */

(function () {
  'use strict';

  /* ── Mobile nav toggle ──────────────────────────────────── */
  const toggle   = document.getElementById('nav-toggle');
  const mobileNav = document.getElementById('nav-mobile');

  if (toggle && mobileNav) {
    toggle.addEventListener('click', () => {
      const isOpen = mobileNav.classList.toggle('open');
      toggle.classList.toggle('open', isOpen);
      toggle.setAttribute('aria-expanded', isOpen);
      document.body.style.overflow = isOpen ? 'hidden' : '';
    });

    // Close on any nav link click
    mobileNav.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        mobileNav.classList.remove('open');
        toggle.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
      });
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
      if (!toggle.contains(e.target) && !mobileNav.contains(e.target)) {
        mobileNav.classList.remove('open');
        toggle.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
        document.body.style.overflow = '';
      }
    });
  }

  /* ── Active nav link ────────────────────────────────────── */
  function setActiveNavLinks() {
    const raw = window.location.pathname.split('/').pop() || '';
    // Normalize: strip .html extension so /about and /about.html both match
    const currentPath = raw.replace(/\.html$/, '') || 'index';
    document.querySelectorAll('.nav-links a, .nav-mobile a').forEach(link => {
      const linkPath = link.getAttribute('href') || '';
      const linkFile = linkPath.split('/').pop().replace(/\.html$/, '') || 'index';
      if (linkFile === currentPath) link.classList.add('active');
    });
  }

  setActiveNavLinks();

  /* ── Scroll reveal ──────────────────────────────────────── */
  const revealEls = document.querySelectorAll('.reveal');

  if ('IntersectionObserver' in window && revealEls.length) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

    revealEls.forEach(el => observer.observe(el));
  } else {
    // Fallback: show all immediately
    revealEls.forEach(el => el.classList.add('visible'));
  }

  /* ── Sermons (from /api/sermons, the church YouTube feed) ── */
  // Home shows the 3 newest; /sermons shows the 9 newest that match the
  // active filter. The feed carries ~15, so a filter still has older videos
  // to draw on.
  const sermonsEl = document.querySelector('[data-sermons]');
  const CHANNEL_URL = 'https://www.youtube.com/@cpcofc/videos';
  const SHOW = { recent: 3, all: 9 };
  const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  let allVideos = [];

  /** Tiny DOM builder — all feed text goes in via textContent, never innerHTML. */
  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === 'text') node.textContent = v;
      else node.setAttribute(k, v);
    });
    (children || []).forEach(c => c && node.appendChild(c));
    return node;
  }

  function playIcon() {
    const wrap = document.createElement('span');
    wrap.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><polygon points="6,3 20,12 6,21"/></svg>';
    return wrap.firstChild;
  }

  /** "2026-10-04" → "Oct 4, 2026" without timezone shifts. */
  function formatDate(date) {
    const [y, m, d] = date.split('-').map(Number);
    return `${MONTHS[m - 1]} ${d}, ${y}`;
  }

  /**
   * Sharpest thumbnail YouTube has: 1280px, then 640px, then 480px. A missing
   * size is either a 404 or a 120×90 grey placeholder, so step down on both.
   * The 4:3 sizes are letterboxed; object-fit: cover crops the bars off.
   */
  const THUMBS = ['maxresdefault.jpg', 'sddefault.jpg', 'hqdefault.jpg'];

  function thumbnail(id) {
    const base = 'https://i.ytimg.com/vi/' + encodeURIComponent(id) + '/';
    let i = 0;
    const img = el('img', { class: 'sermon-tile-img', src: base + THUMBS[0], alt: '', decoding: 'async' });
    const stepDown = () => { if (i < THUMBS.length - 1) img.src = base + THUMBS[++i]; };
    img.addEventListener('error', stepDown);
    img.addEventListener('load', () => { if (img.naturalWidth <= 120) stepDown(); });
    return img;
  }

  function sermonTile(v) {
    const btn = el('button', { class: 'sermon-tile-play', type: 'button',
                               'aria-label': 'Play ' + v.title },
                   [el('span', { class: 'sermon-tile-ring', 'aria-hidden': 'true' }, [playIcon()])]);

    const tile = el('article', {
      class: 'sermon-tile',
      'data-category': v.category,
    }, [
      thumbnail(v.videoId),
      el('span', { class: 'sermon-tile-shade', 'aria-hidden': 'true' }),
      el('span', { class: 'sermon-chip', text: v.category }),
      el('div', { class: 'sermon-tile-text' }, [
        el('h3', { text: v.title }),
        el('p', { class: 'sermon-tile-meta', text: formatDate(v.date) }),
      ]),
      btn,
    ]);

    btn.addEventListener('click', () => openPlayer(v, btn));
    return tile;
  }

  /**
   * Clicking a tile opens it in a large player over the page, with a link out
   * to YouTube. Closing removes the iframe, which stops playback.
   */
  let player, playerReturnFocus;

  function buildPlayer() {
    const closeBtn = el('button', { class: 'player-close', type: 'button', 'aria-label': 'Close video' });
    closeBtn.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>';

    const dlg = el('dialog', { class: 'player', 'aria-labelledby': 'player-title' }, [
      el('div', { class: 'player-inner' }, [
        closeBtn,
        el('div', { class: 'player-frame' }),
        el('div', { class: 'player-info' }, [
          el('div', {}, [
            el('p', { class: 'player-meta' }),
            el('h3', { id: 'player-title' }),
          ]),
          el('a', { class: 'btn btn-primary player-yt', target: '_blank', rel: 'noopener',
                    text: 'Open in YouTube' }),
        ]),
      ]),
    ]);

    closeBtn.addEventListener('click', () => dlg.close());
    // A click on the dark backdrop lands on the <dialog> itself
    dlg.addEventListener('click', e => { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener('close', () => {
      dlg.querySelector('.player-frame').replaceChildren();
      document.documentElement.classList.remove('player-open');
      playerReturnFocus?.focus();
    });
    document.body.appendChild(dlg);
    return dlg;
  }

  function openPlayer(v, returnFocus) {
    player = player || buildPlayer();
    playerReturnFocus = returnFocus;
    const id = encodeURIComponent(v.videoId);

    player.querySelector('#player-title').textContent = v.title;
    player.querySelector('.player-meta').textContent = v.meta || (v.category + ' · ' + formatDate(v.date));
    player.querySelector('.player-yt').href = 'https://www.youtube.com/watch?v=' + id;
    player.querySelector('.player-frame').replaceChildren(el('iframe', {
      src: `https://www.youtube-nocookie.com/embed/${id}?autoplay=1&rel=0`,
      title: v.title,
      allow: 'autoplay; encrypted-media; picture-in-picture; fullscreen',
      allowfullscreen: '',
    }));

    document.documentElement.classList.add('player-open');
    player.showModal();
    player.querySelector('.player-close').focus();
  }

  function sermonsStatus(text) {
    const p = el('p', { class: 'sermons-status', text: text + ' ' });
    p.appendChild(el('a', { href: CHANNEL_URL, target: '_blank', rel: 'noopener',
                            text: 'Watch on YouTube' }));
    return p;
  }

  function renderSermons(category) {
    const mode  = sermonsEl.dataset.sermons;
    const shown = allVideos
      .filter(v => !category || category === 'All' || v.category === category)
      .slice(0, SHOW[mode] || 9);

    sermonsEl.replaceChildren(...shown.map(v => sermonTile(v)));
    if (!shown.length) sermonsEl.appendChild(sermonsStatus('No recent videos in this category.'));
  }

  if (sermonsEl) {
    fetch('/api/sermons')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(({ videos }) => {
        if (!videos || !videos.length) throw new Error('empty');
        allVideos = videos;
        renderSermons(document.querySelector('.filter-btn.active')?.dataset.filter);
      })
      .catch(() => {
        sermonsEl.replaceChildren(sermonsStatus("We couldn't load recent sermons right now."));
      });
  }

  const filterBtns = document.querySelectorAll('.filter-btn');

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => { b.classList.remove('active'); b.setAttribute('aria-pressed', 'false'); });
      btn.classList.add('active');
      btn.setAttribute('aria-pressed', 'true');
      if (sermonsEl && allVideos.length) renderSermons(btn.dataset.filter);
    });
  });

  /* ── Live stream banner (from /api/live) ───────────────── */
  // YouTube's /live link lands on a stale video when nothing is on, so the
  // banner only offers "Watch Live" while the Worker says we're actually live.
  const liveBanner = document.querySelector('[data-live-banner]');

  if (liveBanner) {
    const part = name => liveBanner.querySelector(`[data-live-${name}]`);
    const liveBtn = part('btn');
    const offline = {
      label: part('label').textContent, title: part('title').textContent,
      text: part('text').textContent, btn: liveBtn.textContent, href: liveBtn.href,
    };
    let liveVideo = null;

    liveBtn.addEventListener('click', e => {
      if (!liveVideo) return;              // offline: a plain link to past streams
      e.preventDefault();
      openPlayer(liveVideo, liveBtn);
    });

    const show = (state, label, title, text, btn, href) => {
      liveBanner.classList.toggle('is-live', state === 'live');
      liveBanner.classList.toggle('is-upcoming', state === 'upcoming');
      part('label').textContent = label;
      part('title').textContent = title;
      part('text').textContent  = text;
      liveBtn.textContent = btn;
      liveBtn.href = href;
    };

    const checkLive = () => fetch('/api/live')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        const watch = d.videoId && 'https://www.youtube.com/watch?v=' + encodeURIComponent(d.videoId);
        liveVideo = null;
        if (d.status === 'live') {
          liveVideo = { videoId: d.videoId, title: d.title || 'Live from Chase Park', meta: 'Live now' };
          show('live', 'Live Now', d.title || "We're live", 'Join us now — watch right here or on YouTube.',
               'Watch Live', watch);
        } else if (d.status === 'upcoming') {
          const at = new Date(d.startsAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
          show('upcoming', 'Starting Soon', d.title || 'Live stream starting soon',
               `We go live at ${at}. Check back then, or open it on YouTube to get notified.`,
               'Open on YouTube', watch);
        } else {
          show('offline', offline.label, offline.title, offline.text, offline.btn, offline.href);
        }
      })
      .catch(() => {});                    // keep whatever the banner shows now

    checkLive();
    // Recheck every 2 minutes while the tab is open, so it flips to live on its own
    setInterval(() => { if (!document.hidden) checkLive(); }, 2 * 60 * 1000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) checkLive(); });
  }

  /* ── Contact form ───────────────────────────────────────── */
  const contactForm = document.getElementById('contact-form');

  if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const btn = contactForm.querySelector('[type="submit"]');
      const original = btn.textContent;
      btn.textContent = 'Message Sent!';
      btn.disabled = true;
      btn.style.background = '#4ade80';
      btn.style.borderColor = '#4ade80';
      btn.style.color = '#1a3520';
      setTimeout(() => {
        btn.textContent = original;
        btn.disabled = false;
        btn.style.cssText = '';
        contactForm.reset();
      }, 4000);
    });
  }

})();
