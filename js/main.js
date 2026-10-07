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
  // Home shows the 3 newest; /sermons shows the 6 newest that match the
  // active filter, the first one featured large. The feed carries ~15, so a
  // filter still has older videos to draw on.
  const sermonsEl = document.querySelector('[data-sermons]');
  const CHANNEL_URL = 'https://www.youtube.com/@cpcofc/videos';
  const SHOW = { recent: 3, all: 6 };
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

  function sermonTile(v, featured) {
    const btn = el('button', { class: 'sermon-tile-play', type: 'button',
                               'aria-label': 'Play ' + v.title },
                   [el('span', { class: 'sermon-tile-ring', 'aria-hidden': 'true' }, [playIcon()])]);

    const tile = el('article', {
      class: 'sermon-tile' + (featured ? ' sermon-tile--featured' : ''),
      'data-category': v.category,
    }, [
      thumbnail(v.videoId),
      el('span', { class: 'sermon-tile-shade', 'aria-hidden': 'true' }),
      el('span', { class: 'sermon-chip', text: v.category }),
      el('div', { class: 'sermon-tile-text' }, [
        featured ? el('span', { class: 'sermon-tile-eyebrow', text: 'Latest message' }) : null,
        el('h3', { text: v.title }),
        el('p', { class: 'sermon-tile-meta', text: formatDate(v.date) }),
        featured && v.description ? el('p', { class: 'sermon-tile-desc', text: v.description }) : null,
      ]),
      btn,
    ]);

    btn.addEventListener('click', () => {
      closePlayers();
      tile.classList.add('playing');
      const frame = el('iframe', {
        class: 'sermon-embed',
        src: `https://www.youtube-nocookie.com/embed/${encodeURIComponent(v.videoId)}?autoplay=1&rel=0`,
        title: v.title,
        allow: 'autoplay; encrypted-media; picture-in-picture; fullscreen',
        allowfullscreen: '',
      });
      tile.appendChild(frame);
      frame.focus();
    });
    return tile;
  }

  /** Only one inline player at a time; removing the iframe stops playback. */
  function closePlayers() {
    document.querySelectorAll('.sermon-tile.playing').forEach(t => {
      t.classList.remove('playing');
      t.querySelector('.sermon-embed')?.remove();
    });
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
      .slice(0, SHOW[mode] || 6);

    sermonsEl.replaceChildren(...shown.map((v, i) => sermonTile(v, mode === 'all' && i === 0)));
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
