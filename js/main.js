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
  const sermonsEl = document.querySelector('[data-sermons]');
  const CHANNEL_URL = 'https://www.youtube.com/@cpcofc/videos';
  const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const MONTHS_LONG = ['January','February','March','April','May','June','July',
                       'August','September','October','November','December'];

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

  function svg(markup, viewBox) {
    const wrap = document.createElement('span');
    wrap.innerHTML = `<svg viewBox="${viewBox || '0 0 24 24'}" aria-hidden="true">${markup}</svg>`;
    return wrap.firstChild;
  }

  const PLAY   = '<polygon points="5,3 19,12 5,21"/>';
  const VIDEO  = '<polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/>';
  const ARROW  = '<path d="M5 12h14M12 5l7 7-7 7"/>';

  /** "2026-10-04" → { y, m, d } without timezone shifts. */
  function parts(date) {
    const [y, m, d] = date.split('-').map(Number);
    return { y, m: m - 1, d };
  }

  const watchUrl = v => 'https://www.youtube.com/watch?v=' + encodeURIComponent(v.videoId);

  function sermonCard(v) {
    const { y, m, d } = parts(v.date);
    const thumb = el('a', {
      class: 'sermon-card-thumb', href: watchUrl(v), target: '_blank', rel: 'noopener',
      'aria-label': 'Watch ' + v.title + ' on YouTube',
    }, [el('div', { class: 'play-icon' }, [svg(PLAY)])]);
    thumb.style.backgroundImage =
      `url("https://i.ytimg.com/vi/${encodeURIComponent(v.videoId)}/hqdefault.jpg")`;

    const link = el('a', { class: 'sermon-link', href: watchUrl(v), target: '_blank', rel: 'noopener' });
    link.append('Watch ', svg(ARROW));
    link.lastChild.setAttribute('stroke-width', '2');

    return el('article', { class: 'sermon-card reveal visible' }, [
      thumb,
      el('div', { class: 'sermon-card-body' }, [
        el('p', { class: 'sermon-meta', text: `${MONTHS_LONG[m]} ${d}, ${y}  ·  ${v.category}` }),
        el('h3', { text: v.title }),
        v.description ? el('p', { text: v.description }) : el('p'),
        link,
      ]),
    ]);
  }

  function sermonRow(v) {
    const { y, m, d } = parts(v.date);
    const btn = el('button', {
      class: 'icon-btn', type: 'button', 'aria-expanded': 'false',
      'aria-label': 'Watch ' + v.title,
    }, [svg(VIDEO)]);

    const row = el('article', { class: 'sermon-row reveal visible', 'data-category': v.category }, [
      el('div', { class: 'sermon-row-date', 'aria-label': `${MONTHS_LONG[m]} ${d}, ${y}` }, [
        el('span', { class: 'month', text: MONTHS[m] }),
        el('span', { class: 'day', text: String(d) }),
      ]),
      el('div', { class: 'sermon-row-info' }, [
        el('h3', { text: v.title }),
        el('p', { class: 'meta' }, [
          v.description ? el('span', { text: v.description }) : null,
          el('span', { text: v.category }),
          el('span', { text: String(y) }),
        ]),
      ]),
      el('div', { class: 'sermon-row-actions' }, [btn]),
    ]);

    btn.addEventListener('click', () => {
      const open = row.classList.contains('playing');
      closePlayers();
      if (open) return;
      row.classList.add('playing');
      btn.setAttribute('aria-expanded', 'true');
      row.appendChild(el('iframe', {
        class: 'sermon-embed',
        src: `https://www.youtube-nocookie.com/embed/${encodeURIComponent(v.videoId)}?autoplay=1&rel=0`,
        title: v.title,
        allow: 'autoplay; encrypted-media; picture-in-picture; fullscreen',
        allowfullscreen: '',
      }));
    });
    return row;
  }

  /** Only one inline player at a time; removing the iframe stops playback. */
  function closePlayers() {
    document.querySelectorAll('.sermon-row.playing').forEach(r => {
      r.classList.remove('playing');
      r.querySelector('.sermon-embed')?.remove();
      r.querySelector('.icon-btn')?.setAttribute('aria-expanded', 'false');
    });
  }

  function sermonsStatus(text) {
    const p = el('p', { class: 'sermons-status', text: text + ' ' });
    p.appendChild(el('a', { href: CHANNEL_URL, target: '_blank', rel: 'noopener',
                            text: 'Watch on YouTube' }));
    return p;
  }

  function applyFilter(category) {
    let shown = 0;
    sermonsEl.querySelectorAll('.sermon-row').forEach(row => {
      const match = category === 'All' || row.dataset.category === category;
      row.hidden = !match;
      if (match) shown++;
      else if (row.classList.contains('playing')) closePlayers();
    });
    sermonsEl.querySelector('.sermons-status')?.remove();
    if (!shown) sermonsEl.appendChild(sermonsStatus('No recent videos in this category.'));
  }

  if (sermonsEl) {
    const mode = sermonsEl.dataset.sermons;

    fetch('/api/sermons')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(({ videos }) => {
        sermonsEl.replaceChildren();
        if (!videos || !videos.length) throw new Error('empty');
        if (mode === 'recent') videos.slice(0, 3).forEach(v => sermonsEl.appendChild(sermonCard(v)));
        else                   videos.forEach(v => sermonsEl.appendChild(sermonRow(v)));
        const active = document.querySelector('.filter-btn.active');
        if (active) applyFilter(active.dataset.filter);
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
      if (sermonsEl) applyFilter(btn.dataset.filter);
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
