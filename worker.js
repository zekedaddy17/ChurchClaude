/**
 * Chase Park Church of Christ — Cloudflare Worker
 *
 * Routes:
 *   POST /api/register                  — request a member account (pending approval)
 *   POST /api/login                     — verify credentials, issue session cookie
 *   GET  /api/logout                    — clear session, redirect home
 *   GET  /api/session                   — current session info (for client-side checks)
 *   GET  /api/directory                 — directory JSON (approved members only)
 *   GET  /api/admin/users               — pending approval queue (admins only)
 *   POST /api/admin/users/approve       — approve a pending account (admins only)
 *   POST /api/admin/users/deny          — deny + remove a pending account (admins only)
 *   POST /api/admin/directory/import    — replace the directory (admins only)
 *   GET  /api/sermons                   — latest videos from the church YouTube channel
 *   GET  /api/live                      — whether the channel is streaming right now
 *   GET  /members                       — auth-gated portal
 *   GET  /members/directory             — auth-gated member directory
 *   GET  /members/admin                 — admin-gated approvals + directory import
 *   *                                   — fall through to static assets
 *
 * SECURITY NOTES — read before adding pages or routes.
 *
 * 1. Members-only HTML is built HERE, never stored as a file. The repo root is
 *    the public asset store (wrangler.toml: [assets] directory = "."), and the
 *    CDN has previously served an asset before this Worker ran despite
 *    run_worker_first = true (see commit f708fbe). A members-only .html file at
 *    the repo root would be world-readable.
 * 2. Anything under /members that is not a known route is rejected below,
 *    BEFORE the env.ASSETS.fetch fall-through, so a future stray file cannot
 *    reintroduce that bypass.
 * 3. Admin identity comes from the ADMIN_EMAILS secret compared against the
 *    session email on every request. It is never written to the user record
 *    (registration is self-serve, so a stored role would be a land-grab) and
 *    never trusted from the session payload (sessions last 7 days, so a stored
 *    role would outlive a revocation).
 */

const SESSION_TTL  = 60 * 60 * 24 * 7;   // 7 days in seconds
const PBKDF2_ITERS = 100_000;

// Import guard rails. These exist to fail loudly if the "one KV value holds the
// whole directory" assumption ever stops holding — see the plan's sizing notes.
const MAX_DIRECTORY_ROWS  = 5000;
const MAX_DIRECTORY_BYTES = 2 * 1024 * 1024;
const MAX_PENDING_QUEUE   = 500;         // registration backstop against bot floods

// Sermons come from the public YouTube feed for @cpcofc (latest 15 uploads, no
// API key). The feed intermittently 404s/500s, so the last good copy is kept in
// KV and served whenever a refresh fails.
const YT_CHANNEL_ID    = 'UCRk-B6eJNGd8zC8wE8_sk7A';
const YT_FEED_URL      = `https://www.youtube.com/feeds/videos.xml?channel_id=${YT_CHANNEL_ID}`;
const SERMON_CACHE_KEY = 'sermons:feed';
const SERMON_CACHE_TTL = 30 * 60 * 1000;  // ms
const YT_LIVE_URL      = `https://www.youtube.com/channel/${YT_CHANNEL_ID}/live`;
const LIVE_CACHE_TTL   = 60 * 1000;       // ms
const UPCOMING_WINDOW  = 3 * 60 * 60;     // s — only call a scheduled stream "upcoming" this close to its start

// ── Crypto helpers ─────────────────────────────────────────────────────────

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes.buffer;
}

async function hashPassword(password, saltHex) {
  const enc  = new TextEncoder();
  const key  = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBuf(saltHex), iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    key, 256
  );
  return bufToHex(bits);
}

async function newSalt() {
  return bufToHex(crypto.getRandomValues(new Uint8Array(16)).buffer);
}

// ── Cookie helpers ──────────────────────────────────────────────────────────

const TOKEN_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function getSessionToken(request) {
  const match = (request.headers.get('Cookie') || '')
    .match(/(?:^|;\s*)session=([^;]+)/);
  if (!match) return null;
  // Validate the shape before it becomes a KV key: KV keys cap at 512 bytes and
  // an oversized cookie would throw rather than simply miss.
  return TOKEN_RE.test(match[1]) ? match[1] : null;
}

function cookieHeader(token, maxAge = SESSION_TTL) {
  return `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

// ── Response helpers ────────────────────────────────────────────────────────

const NO_CACHE = { 'Cache-Control': 'no-store, no-cache, private' };

function jsonResp(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...NO_CACHE, ...extraHeaders },
  });
}

function htmlResp(html, status = 200) {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html;charset=UTF-8', ...NO_CACHE },
  });
}

function redirectTo(url, extraHeaders = {}) {
  return new Response(null, {
    status: 302,
    headers: { Location: url, ...NO_CACHE, ...extraHeaders },
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Auth helpers ────────────────────────────────────────────────────────────

function adminEmails(env) {
  return String(env.ADMIN_EMAILS || '')
    .split(',')
    .map(e => e.toLowerCase().trim())
    .filter(Boolean);
}

function isAdminEmail(email, env) {
  return adminEmails(env).includes(String(email || '').toLowerCase().trim());
}

/**
 * Accounts created before the approval queue existed have no `status` field.
 * Absent MUST mean approved — if it meant pending, deploying this would lock out
 * every existing member, including the only person able to approve them.
 * Backfill those records, then this default becomes dead code rather than a
 * standing bypass.
 */
function isApproved(user) {
  return (user.status || 'approved') === 'approved';
}

async function getSession(request, env) {
  const token = getSessionToken(request);
  if (!token) return null;
  const raw = await env.MEMBERS_KV.get(`session:${token}`);
  return raw ? JSON.parse(raw) : null;
}

/**
 * Resolve the caller to a live, approved user record.
 *
 * Deliberately re-reads `user:<email>` on every gated request rather than
 * trusting the session payload. Costs one KV read (a subrequest, not CPU, so
 * it is cheap on the Free plan) and is what makes a denial take effect
 * immediately instead of whenever the 7-day session happens to expire.
 */
async function requireSession(request, env) {
  const session = await getSession(request, env);
  if (!session) return null;
  const raw = await env.MEMBERS_KV.get(`user:${session.email}`);
  if (!raw) return null;
  const user    = JSON.parse(raw);
  const isAdmin = isAdminEmail(session.email, env);
  // An ADMIN_EMAILS address counts as approved. Without this the very first
  // admin deadlocks: they sign up through the open form (which makes them
  // pending) and there is nobody able to approve them. ADMIN_EMAILS is a
  // deployment secret, not user input, so this is safe.
  if (!isAdmin && !isApproved(user)) return null;
  return { session, user, isAdmin };
}

async function requireAdmin(request, env) {
  const auth = await requireSession(request, env);
  return auth && auth.isAdmin ? auth : null;
}

/**
 * SameSite=Strict is the primary CSRF defense, but a single admin POST can
 * replace the entire roster, so check the Origin too. JSON bodies already force
 * a preflight cross-origin; this covers the rest.
 */
function sameOrigin(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return true;               // same-origin navigations may omit it
  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch {
    return false;
  }
}

// ── Shared page chrome ──────────────────────────────────────────────────────

const NAV_ITEMS = [
  { href: '/',         label: 'Home',     key: 'home' },
  { href: '/about',    label: 'About',    key: 'about' },
  { href: '/sermons',  label: 'Sermons',  key: 'sermons' },
  { href: '/members',  label: 'Members',  key: 'members' },
];

/**
 * Every members-only page is built through here. Keeping the chrome in one
 * place is what makes it practical to inline three pages in the Worker rather
 * than adding HTML files that the asset layer could serve unauthenticated.
 */
function renderPage({ title, activeNav, bodyHtml, headExtra = '', scriptHtml = '' }) {
  const navLinks = NAV_ITEMS.map(item =>
    `<li><a href="${item.href}"${item.key === activeNav ? ' class="active"' : ''}>${item.label}</a></li>`
  ).join('\n        ');

  const navMobile = NAV_ITEMS.map(item =>
    `<a href="${item.href}"${item.key === activeNav ? ' class="active"' : ''}>${item.label}</a>`
  ).join('\n    ');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)} — Chase Park Church of Christ</title>
  <meta name="description" content="Members-only area for Chase Park Church of Christ." />
  <meta name="robots" content="noindex, nofollow" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Lato:wght@300;400;700&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/css/style.css" />
${headExtra}
</head>
<body>
  <header class="site-header">
    <nav class="nav-inner" aria-label="Main navigation">
      <a href="/" class="nav-logo" aria-label="Chase Park Church of Christ — Home">
        <span class="name">Chase Park</span>
        <span class="sub">Church of Christ</span>
      </a>
      <ul class="nav-links" role="list">
        ${navLinks}
        <li><a href="/contact" class="nav-cta">Visit Us</a></li>
      </ul>
      <button class="nav-toggle" id="nav-toggle" aria-label="Open menu" aria-expanded="false" aria-controls="nav-mobile">
        <span></span><span></span><span></span>
      </button>
    </nav>
  </header>
  <nav class="nav-mobile" id="nav-mobile" aria-label="Mobile navigation">
    ${navMobile}
    <a href="/contact">Visit Us</a>
  </nav>
  <main>
${bodyHtml}
  </main>
  <footer class="site-footer">
    <div class="container">
      <div class="footer-grid">
        <div class="footer-brand">
          <p class="name">Chase Park</p>
          <p class="sub">Church of Christ</p>
          <p>A community of faith in Huntsville, Alabama — rooted in Scripture and committed to love.</p>
        </div>
        <div class="footer-col">
          <h4>Navigate</h4>
          <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/about">About</a></li>
            <li><a href="/sermons">Sermons</a></li>
            <li><a href="/contact">Contact</a></li>
          </ul>
        </div>
        <div class="footer-col">
          <h4>Service Times</h4>
          <ul>
            <li><a href="/contact">Sunday 9:00 AM</a></li>
            <li><a href="/contact">Sunday 10:15 AM</a></li>
            <li><a href="/contact">Sunday 5:00 PM</a></li>
            <li><a href="/contact">Wednesday 6:30 PM</a></li>
          </ul>
        </div>
        <div class="footer-col">
          <h4>Contact</h4>
          <address>
            1640 Winchester Rd. N.E.<br>Huntsville, AL 35811<br><br>
            <a href="tel:+12568523801">(256) 852-3801</a><br>Mon–Fri, 8 AM–3 PM
          </address>
        </div>
      </div>
      <p class="footer-bottom">&copy; <span id="year"></span> Chase Park Church of Christ. All rights reserved.</p>
    </div>
  </footer>
  <script>document.getElementById('year').textContent = new Date().getFullYear();</script>
  <script src="/js/main.js"></script>
${scriptHtml}
</body>
</html>`;
}

/** Standard members-only page hero with a Sign Out action. */
function portalHero({ label, heading, sub, extraActions = '' }) {
  return `    <section class="page-hero" aria-labelledby="page-heading">
      <div class="container">
        <div class="page-hero-content portal-hero-content">
          <span class="section-label">${escapeHtml(label)}</span>
          <h1 id="page-heading">${escapeHtml(heading)}</h1>
          <p class="portal-hero-sub">${escapeHtml(sub)}</p>
          <div class="portal-hero-actions">
${extraActions}
            <a href="/api/logout" class="btn btn-outline">Sign Out</a>
          </div>
        </div>
      </div>
    </section>`;
}

// ── Members portal ──────────────────────────────────────────────────────────

const ICON_ARROW = '<svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';

function portalCard({ icon, title, body, href, linkText }) {
  const link = href
    ? `<a href="${href}" class="portal-card-link">${linkText} ${ICON_ARROW}</a>`
    : `<span class="portal-card-link portal-card-soon">Coming soon</span>`;
  return `          <div class="portal-card reveal">
            <div class="portal-card-icon" aria-hidden="true">${icon}</div>
            <h3>${title}</h3>
            <p>${body}</p>
            ${link}
          </div>`;
}

function buildMembersPage(memberName, isAdmin) {
  const cards = [
    portalCard({
      icon: '<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
      title: 'Weekly Bulletin',
      body: "The current week's bulletin with announcements, schedule updates, and congregational news.",
    }),
    portalCard({
      icon: '<svg viewBox="0 0 24 24"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12 19.79 19.79 0 0 1 1.61 3.4 2 2 0 0 1 3.6 1.22h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.82a16 16 0 0 0 6.29 6.29l.95-.95a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>',
      title: 'Newsline',
      body: 'Member announcements, prayer requests, celebrations, and important congregational updates.',
    }),
    portalCard({
      icon: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>',
      title: 'Church Calendar',
      body: 'Full schedule of upcoming services, classes, events, fellowships, and ministry activities.',
    }),
    portalCard({
      icon: '<svg viewBox="0 0 24 24"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>',
      title: 'Prayer List',
      body: 'Current prayer requests from congregation members. Pray for one another and submit your own requests.',
    }),
    portalCard({
      icon: '<svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
      title: 'Member Directory',
      body: 'Contact information for our church family, kept current from the church office records.',
      href: '/members/directory',
      linkText: 'View Directory',
    }),
    portalCard({
      icon: '<svg viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>',
      title: 'Bible Study Materials',
      body: 'Class notes, study guides, and handouts from Sunday and Wednesday Bible classes.',
    }),
  ];

  if (isAdmin) {
    cards.push(portalCard({
      icon: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
      title: 'Church Administration',
      body: 'Approve new member accounts and refresh the directory from a Servant Keeper export.',
      href: '/members/admin',
      linkText: 'Open Admin',
    }));
  }

  const body = `${portalHero({
    label: 'Members Only',
    heading: `Welcome, ${memberName}`,
    sub: "You're signed in to the Chase Park members portal.",
  })}
    <section class="section">
      <div class="container">
        <div class="section-header reveal">
          <span class="section-label">Resources</span>
          <h2>Member Resources</h2>
          <p>Everything you need to stay connected and informed as part of our church family.</p>
        </div>
        <div class="portal-grid">
${cards.join('\n')}
        </div>
      </div>
    </section>
    <section class="scripture-section" aria-label="Scripture">
      <div class="container">
        <blockquote>
          <p class="scripture-text">"Therefore encourage one another and build one another up, just as you are doing."</p>
          <footer class="scripture-ref">1 Thessalonians 5:11</footer>
        </blockquote>
      </div>
    </section>`;

  return renderPage({ title: 'Members Portal', activeNav: 'members', bodyHtml: body });
}

// ── Member directory page ───────────────────────────────────────────────────

/**
 * Shell only. The roster arrives from the gated /api/directory and is rendered
 * client-side with textContent — never innerHTML, and never interpolated into
 * the page source, because these values come from a spreadsheet the church
 * office maintains and a cell containing markup would otherwise be stored XSS.
 */
function buildDirectoryPage() {
  const body = `${portalHero({
    label: 'Members Only',
    heading: 'Church Directory',
    sub: 'Contact information for our church family. Please treat it with care.',
    extraActions: '            <a href="/members" class="btn btn-outline">Back to Portal</a>\n',
  })}
    <section class="section">
      <div class="container">
        <div class="directory-toolbar">
          <div class="form-group directory-search">
            <label for="dir-search">Search the directory</label>
            <input type="search" id="dir-search" placeholder="Name, phone, street…"
              autocomplete="off" spellcheck="false" />
          </div>
          <p class="directory-count" id="dir-count" aria-live="polite"></p>
        </div>

        <div id="dir-status" class="auth-banner auth-error" hidden>
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span id="dir-status-text"></span>
        </div>

        <div class="portal-grid" id="dir-grid"></div>
        <p class="directory-updated" id="dir-updated"></p>
      </div>
    </section>`;

  const script = `<script>
(function () {
  var grid    = document.getElementById('dir-grid');
  var count   = document.getElementById('dir-count');
  var updated = document.getElementById('dir-updated');
  var search  = document.getElementById('dir-search');
  var status  = document.getElementById('dir-status');
  var statusT = document.getElementById('dir-status-text');
  var data    = null;

  function fail(msg) { statusT.textContent = msg; status.hidden = false; }

  function initials(text) {
    var parts = text.trim().split(/\\s+/).filter(Boolean);
    if (!parts.length) return '?';
    if (parts.length === 1) return parts[0].charAt(0).toUpperCase();
    return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
  }

  function displayName(row) {
    var picked = data.nameColumns.map(function (i) { return row[i]; })
                   .filter(function (v) { return v && v.trim(); });
    return picked.join(' ').trim();
  }

  // Every value below is set with textContent. Do not switch to innerHTML.
  function card(row) {
    var wrap = document.createElement('div');
    wrap.className = 'portal-card directory-card';

    var head = document.createElement('div');
    head.className = 'directory-card-head';

    var name = displayName(row) || 'Unnamed record';
    var av   = document.createElement('div');
    av.className = 'leader-avatar directory-avatar';
    av.setAttribute('aria-hidden', 'true');
    av.textContent = initials(name);
    head.appendChild(av);

    var h3 = document.createElement('h3');
    h3.textContent = name;
    head.appendChild(h3);
    wrap.appendChild(head);

    var dl = document.createElement('dl');
    dl.className = 'directory-fields';
    data.columns.forEach(function (col, i) {
      if (data.nameColumns.indexOf(i) !== -1) return;
      var val = row[i];
      if (!val || !val.trim()) return;

      var dt = document.createElement('dt');
      dt.textContent = col;
      var dd = document.createElement('dd');

      // Make contact details actionable, but build the href from the value
      // rather than trusting it as markup.
      if (/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(val.trim())) {
        var a = document.createElement('a');
        a.href = 'mailto:' + val.trim();
        a.textContent = val;
        dd.appendChild(a);
      } else if (/^[+()\\d][\\d\\s().-]{6,}$/.test(val.trim())) {
        var t = document.createElement('a');
        t.href = 'tel:' + val.replace(/[^+\\d]/g, '');
        t.textContent = val;
        dd.appendChild(t);
      } else {
        dd.textContent = val;
      }
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    wrap.appendChild(dl);
    return wrap;
  }

  function render(rows) {
    grid.textContent = '';
    if (!rows.length) {
      var empty = document.createElement('p');
      empty.className = 'directory-empty';
      empty.textContent = data.rows.length
        ? 'No one matches that search.'
        : 'The directory has not been uploaded yet.';
      grid.appendChild(empty);
    } else {
      var frag = document.createDocumentFragment();
      rows.forEach(function (r) { frag.appendChild(card(r)); });
      grid.appendChild(frag);
    }
    count.textContent = rows.length + (rows.length === 1 ? ' entry' : ' entries');
  }

  function filter() {
    var q = search.value.toLowerCase().trim();
    if (!q) return render(data.rows);
    var terms = q.split(/\\s+/);
    render(data.rows.filter(function (row) {
      var hay = data.searchColumns.map(function (i) { return row[i] || ''; })
                  .join(' ').toLowerCase();
      return terms.every(function (t) { return hay.indexOf(t) !== -1; });
    }));
  }

  fetch('/api/directory', { credentials: 'same-origin' })
    .then(function (r) {
      if (r.status === 401 || r.status === 403) { window.location.href = '/login'; return null; }
      if (!r.ok) throw new Error('http ' + r.status);
      return r.json();
    })
    .then(function (d) {
      if (!d) return;
      data = d;
      if (!Array.isArray(data.rows)) data.rows = [];
      if (!Array.isArray(data.columns)) data.columns = [];
      if (!Array.isArray(data.nameColumns) || !data.nameColumns.length) data.nameColumns = [0];
      if (!Array.isArray(data.searchColumns) || !data.searchColumns.length) {
        data.searchColumns = data.columns.map(function (_, i) { return i; });
      }
      if (data.importedAt) {
        updated.textContent = 'Directory last updated ' +
          new Date(data.importedAt).toLocaleDateString(undefined,
            { year: 'numeric', month: 'long', day: 'numeric' });
      }
      render(data.rows);
      search.addEventListener('input', filter);
    })
    .catch(function () { fail('Could not load the directory. Please try again.'); });
})();
</script>`;

  return renderPage({
    title: 'Church Directory',
    activeNav: 'members',
    bodyHtml: body,
    scriptHtml: script,
  });
}

// ── Admin page ──────────────────────────────────────────────────────────────

/**
 * Approvals + directory import.
 *
 * The CSV never reaches this Worker and is never stored anywhere: the browser
 * decodes it, parses it, and uploads only the columns the admin ticked. That is
 * partly a Free-plan necessity (10 ms CPU will not parse thousands of rows) and
 * partly a privacy win — Servant Keeper exports routinely carry contribution
 * totals, birthdates and background-check flags, and unticked columns never
 * leave the admin's machine.
 */
function buildAdminPage() {
  const body = `${portalHero({
    label: 'Administration',
    heading: 'Church Administration',
    sub: 'Approve member accounts and refresh the directory.',
    extraActions: '            <a href="/members" class="btn btn-outline">Back to Portal</a>\n',
  })}
    <section class="section">
      <div class="container">
        <div class="section-header">
          <span class="section-label">Accounts</span>
          <h2>Pending Approvals</h2>
          <p>New sign-ups cannot reach the members area until you approve them here.
             Changes can take up to a minute to take effect everywhere.</p>
        </div>
        <div id="pending-status" class="auth-banner auth-error" hidden>
          <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span id="pending-status-text"></span>
        </div>
        <div id="pending-list" class="admin-list"><p class="directory-empty">Loading…</p></div>
      </div>
    </section>

    <section class="section section--alt">
      <div class="container">
        <div class="section-header">
          <span class="section-label">Directory</span>
          <h2>Update the Directory</h2>
          <p>Export from Servant Keeper (Membership Manager → Groups Keeper → select your group →
             Select Fields → Group tab → Export → CSV), then choose the file below.
             The file stays on this computer — only the columns you tick are uploaded.</p>
        </div>

        <p class="admin-meta" id="import-meta"></p>

        <div class="form-group">
          <label for="csv-file">Servant Keeper CSV export</label>
          <input type="file" id="csv-file" accept=".csv,text/csv" />
        </div>

        <div id="import-status" class="auth-banner" hidden>
          <span id="import-status-text"></span>
        </div>

        <div id="mapper" hidden>
          <p class="admin-hint">
            Nothing is published unless you tick <strong>Show</strong>. Tick <strong>Name</strong>
            for the columns that make up each person's displayed name, and <strong>Search</strong>
            for the columns members should be able to search on.
          </p>
          <div class="admin-table-wrap">
            <table class="admin-table">
              <thead>
                <tr><th>Column</th><th>Example</th><th>Show</th><th>Name</th><th>Search</th></tr>
              </thead>
              <tbody id="mapper-rows"></tbody>
            </table>
          </div>
          <div class="admin-actions">
            <button type="button" class="btn btn-primary" id="import-btn">Publish Directory</button>
            <span class="admin-hint" id="import-summary"></span>
          </div>
        </div>
      </div>
    </section>`;

  const script = `<script>
(function () {
  // ── Pending approvals ────────────────────────────────────────────────────
  var list    = document.getElementById('pending-list');
  var pStatus = document.getElementById('pending-status');
  var pText   = document.getElementById('pending-status-text');

  // Accounts approved or denied on this visit. The server can briefly still
  // list them after the change, so they are kept off the page regardless.
  var handled = {};

  function pendingNote(msg, kind) {
    pText.textContent = msg;
    pStatus.className = 'auth-banner ' + (kind === 'ok' ? 'auth-success' : 'auth-error');
    pStatus.hidden = false;
  }
  function pendingFail(msg) { pendingNote(msg, 'error'); }

  function loadPending() {
    fetch('/api/admin/users', { credentials: 'same-origin' })
      .then(function (r) {
        if (r.status === 401 || r.status === 403) { window.location.href = '/members'; return null; }
        if (!r.ok) throw new Error('http ' + r.status);
        return r.json();
      })
      .then(function (d) {
        if (d) renderPending((d.pending || []).filter(function (p) { return !handled[p.email]; }));
      })
      .catch(function () { pendingFail('Could not load pending accounts.'); });
  }

  function renderPending(items) {
    list.textContent = '';
    if (!items.length) {
      var none = document.createElement('p');
      none.className = 'directory-empty';
      none.textContent = 'No accounts are waiting for approval.';
      list.appendChild(none);
      return;
    }
    items.forEach(function (item) {
      var row = document.createElement('div');
      row.className = 'admin-row';

      var info = document.createElement('div');
      var nm = document.createElement('strong');
      nm.textContent = item.name || '(no name given)';
      var em = document.createElement('span');
      em.className = 'admin-row-email';
      em.textContent = item.email;
      info.appendChild(nm);
      info.appendChild(em);
      if (item.createdAt) {
        var when = document.createElement('span');
        when.className = 'admin-row-date';
        when.textContent = 'Requested ' + new Date(item.createdAt).toLocaleDateString();
        info.appendChild(when);
      }
      row.appendChild(info);

      var actions = document.createElement('div');
      actions.className = 'admin-row-actions';
      actions.appendChild(actionBtn('Approve', 'btn btn-primary', item, 'approve', row));
      actions.appendChild(actionBtn('Deny', 'btn btn-outline-dark', item, 'deny', row));
      row.appendChild(actions);

      list.appendChild(row);
    });
  }

  function actionBtn(label, cls, item, action, row) {
    var email = item.email;
    var who   = item.name ? item.name + ' (' + email + ')' : email;
    var b = document.createElement('button');
    b.type = 'button';
    b.className = cls;
    b.textContent = label;
    b.addEventListener('click', function () {
      if (action === 'deny' && !window.confirm('Deny and delete the account for ' + email + '?')) return;
      Array.prototype.forEach.call(row.querySelectorAll('button'), function (x) { x.disabled = true; });
      fetch('/api/admin/users/' + action, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email }),
      })
        .then(function (r) { if (!r.ok) throw new Error('http ' + r.status); return r.json(); })
        .then(function () {
          handled[email] = true;
          row.remove();
          pendingNote(action === 'approve'
            ? 'Approved ' + who + '. They can sign in now (allow up to a minute).'
            : 'Denied ' + who + '. The account was deleted.', 'ok');
          if (!list.querySelector('.admin-row')) renderPending([]);
        })
        .catch(function () {
          pendingFail('Could not ' + action + ' ' + email + '. Please try again.');
          Array.prototype.forEach.call(row.querySelectorAll('button'), function (x) { x.disabled = false; });
        });
    });
    return b;
  }

  loadPending();

  // ── CSV import ───────────────────────────────────────────────────────────
  var fileInput = document.getElementById('csv-file');
  var mapper    = document.getElementById('mapper');
  var mapRows   = document.getElementById('mapper-rows');
  var iStatus   = document.getElementById('import-status');
  var iText     = document.getElementById('import-status-text');
  var iBtn      = document.getElementById('import-btn');
  var iSummary  = document.getElementById('import-summary');
  var iMeta     = document.getElementById('import-meta');
  var parsed    = null;

  function setStatus(msg, kind) {
    iText.textContent = msg;
    iStatus.className = 'auth-banner ' + (kind === 'ok' ? 'auth-success' : 'auth-error');
    iStatus.hidden = false;
  }

  fetch('/api/admin/directory/meta', { credentials: 'same-origin' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (m) {
      if (m && m.importedAt) {
        iMeta.textContent = 'Currently published: ' + m.rowCount + ' entries, ' +
          m.columns.length + ' columns, uploaded ' +
          new Date(m.importedAt).toLocaleString() +
          (m.importedBy ? ' by ' + m.importedBy : '') + '.';
      } else {
        iMeta.textContent = 'No directory has been published yet.';
      }
    })
    .catch(function () {});

  /** RFC 4180: doubled quotes, embedded commas and newlines, CRLF, BOM. */
  function parseCSV(text) {
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    // Normalise first so a Windows CRLF *inside* a quoted field (multi-line
    // addresses have them) doesn't leave a stray CR in the stored value.
    text = text.replace(/\\r\\n/g, '\\n');
    var rows = [], row = [], field = '', i = 0, inQuotes = false;
    while (i < text.length) {
      var c = text.charAt(i);
      if (inQuotes) {
        if (c === '"') {
          if (text.charAt(i + 1) === '"') { field += '"'; i += 2; continue; }
          inQuotes = false; i++; continue;
        }
        field += c; i++; continue;
      }
      if (c === '"')  { inQuotes = true; i++; continue; }
      if (c === ',')  { row.push(field); field = ''; i++; continue; }
      if (c === '\\r') { i++; continue; }
      if (c === '\\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
      field += c; i++;
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    return rows;
  }

  /**
   * Servant Keeper exports from Windows are often CP1252. Decoded as UTF-8 they
   * silently mangle smart quotes and accented names, so try strict UTF-8 first
   * and fall back only when it actually fails.
   */
  function decode(buffer) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(buffer);
    } catch (e) {
      return new TextDecoder('windows-1252').decode(buffer);
    }
  }

  var NAME_HINTS   = ['firstname','lastname','preferredname','goesby','middlename','name','suffix','nickname'];
  var SHOW_HINTS   = ['email','emailaddress','phone','cellphone','mobilephone','homephone','workphone',
                      'address','addressline1','addressline2','street','city','state','zip','zipcode'];

  function norm(h) { return String(h).toLowerCase().replace(/[^a-z0-9]/g, ''); }

  /**
   * Pre-tick only a conservative whitelist. Everything else starts unticked, so
   * a column nobody recognised is never published by accident.
   */
  function guess(header) {
    var n = norm(header);
    var isName = NAME_HINTS.indexOf(n) !== -1;
    var isShow = isName || SHOW_HINTS.indexOf(n) !== -1;
    return { show: isShow, name: isName, search: isShow };
  }

  fileInput.addEventListener('change', function () {
    var file = fileInput.files && fileInput.files[0];
    mapper.hidden = true;
    iStatus.hidden = true;
    parsed = null;
    if (!file) return;

    file.arrayBuffer().then(function (buf) {
      var rows = parseCSV(decode(buf));
      rows = rows.filter(function (r) { return r.some(function (c) { return c && c.trim(); }); });
      if (rows.length < 2) { setStatus('That file has no data rows.', 'err'); return; }

      var header = rows[0].map(function (h) { return String(h).trim(); });
      var data   = rows.slice(1).map(function (r) {
        var out = [];
        for (var i = 0; i < header.length; i++) out.push(r[i] == null ? '' : String(r[i]).trim());
        return out;
      });

      parsed = { header: header, rows: data };
      buildMapper();
      setStatus('Read ' + data.length + ' rows and ' + header.length +
                ' columns. Nothing is published until you choose columns and press Publish.', 'ok');
    }).catch(function () {
      setStatus('Could not read that file. Make sure it is a .csv export.', 'err');
    });
  });

  function buildMapper() {
    mapRows.textContent = '';
    parsed.header.forEach(function (col, i) {
      var g = guess(col);
      var tr = document.createElement('tr');

      var tdName = document.createElement('td');
      tdName.textContent = col || '(unnamed column ' + (i + 1) + ')';
      tr.appendChild(tdName);

      var sample = '';
      for (var r = 0; r < parsed.rows.length && !sample; r++) sample = parsed.rows[r][i];
      var tdEx = document.createElement('td');
      tdEx.className = 'admin-sample';
      tdEx.textContent = sample || '—';
      tr.appendChild(tdEx);

      ['show', 'name', 'search'].forEach(function (kind) {
        var td = document.createElement('td');
        var cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = g[kind];
        cb.dataset.kind = kind;
        cb.dataset.index = String(i);
        cb.setAttribute('aria-label', kind + ' ' + col);
        cb.addEventListener('change', syncSummary);
        td.appendChild(cb);
        tr.appendChild(td);
      });

      mapRows.appendChild(tr);
    });
    mapper.hidden = false;
    syncSummary();
  }

  function picked(kind) {
    return Array.prototype.slice
      .call(mapRows.querySelectorAll('input[data-kind="' + kind + '"]'))
      .filter(function (cb) { return cb.checked; })
      .map(function (cb) { return parseInt(cb.dataset.index, 10); });
  }

  function syncSummary() {
    var show = picked('show');
    iSummary.textContent = show.length
      ? show.length + ' of ' + parsed.header.length + ' columns will be published.'
      : 'No columns selected — nothing would be published.';
  }

  iBtn.addEventListener('click', function () {
    var show = picked('show');
    if (!show.length) { setStatus('Tick at least one column to show.', 'err'); return; }

    var names = picked('name').filter(function (i) { return show.indexOf(i) !== -1; });
    if (!names.length) { setStatus('Tick at least one Name column so entries have a title.', 'err'); return; }
    var searches = picked('search').filter(function (i) { return show.indexOf(i) !== -1; });
    if (!searches.length) searches = show.slice();

    // Project to the chosen columns and reindex, so unticked data never leaves
    // this machine.
    var payload = {
      columns: show.map(function (i) { return parsed.header[i]; }),
      rows: parsed.rows.map(function (r) { return show.map(function (i) { return r[i]; }); }),
      nameColumns: names.map(function (i) { return show.indexOf(i); }),
      searchColumns: searches.map(function (i) { return show.indexOf(i); }),
    };

    if (!window.confirm('Publish ' + payload.rows.length + ' entries with ' +
        payload.columns.length + ' columns? This replaces the current directory.')) return;

    iBtn.disabled = true;
    iBtn.textContent = 'Publishing…';
    fetch('/api/admin/directory/import', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then(function (r) {
        return r.json().then(function (d) { return { ok: r.ok, data: d }; });
      })
      .then(function (res) {
        if (!res.ok) throw new Error(res.data.error || 'Import failed.');
        setStatus('Published ' + res.data.rowCount + ' entries. Members may see the previous ' +
                  'version for up to a minute.', 'ok');
        fileInput.value = '';
        mapper.hidden = true;
        iMeta.textContent = 'Currently published: ' + res.data.rowCount + ' entries, ' +
          payload.columns.length + ' columns, uploaded just now.';
      })
      .catch(function (e) { setStatus(e.message || 'Import failed.', 'err'); })
      .finally(function () {
        iBtn.disabled = false;
        iBtn.textContent = 'Publish Directory';
      });
  });
})();
</script>`;

  return renderPage({
    title: 'Church Administration',
    activeNav: 'members',
    bodyHtml: body,
    scriptHtml: script,
  });
}

// ── Auth handlers ───────────────────────────────────────────────────────────

/**
 * Registration is a *request*, not an account. The response is deliberately
 * identical whether or not the email already exists — a distinct "already
 * exists" reply would be an enumeration oracle against the church roster.
 */
async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonResp({ error: 'Invalid request body.' }, 400); }

  const { name, email, password } = body;
  if (!name || !email || !password)
    return jsonResp({ error: 'All fields are required.' }, 400);
  if (password.length < 8)
    return jsonResp({ error: 'Password must be at least 8 characters.' }, 400);

  const emailLower = email.toLowerCase().trim();
  const submitted  = { ok: true, message: 'Your request has been submitted for approval.' };

  // Admin accounts must be created before ADMIN_EMAILS is set, never through
  // the open form — otherwise whoever registers an admin address first would
  // inherit admin rights.
  if (isAdminEmail(emailLower, env)) return jsonResp(submitted);

  if (await env.MEMBERS_KV.get(`user:${emailLower}`)) return jsonResp(submitted);

  const queue = await env.MEMBERS_KV.list({ prefix: 'pending:', limit: MAX_PENDING_QUEUE });
  if (!queue.list_complete)
    return jsonResp({ error: 'Registrations are temporarily closed. Please contact the office.' }, 503);

  const salt         = await newSalt();
  const passwordHash = await hashPassword(password, salt);
  const createdAt    = new Date().toISOString();

  await env.MEMBERS_KV.put(`user:${emailLower}`, JSON.stringify({
    name: name.trim(), email: emailLower, passwordHash, salt,
    status: 'pending', createdAt,
  }));
  // Metadata on the index key lets the admin queue render from a single list()
  // call — no per-user get(), which matters against the 50-subrequest cap.
  await env.MEMBERS_KV.put(`pending:${emailLower}`, '', {
    metadata: { name: name.trim(), email: emailLower, createdAt },
  });

  return jsonResp(submitted);
}

async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonResp({ error: 'Invalid request body.' }, 400); }

  const { email, password } = body;
  if (!email || !password)
    return jsonResp({ error: 'Email and password are required.' }, 400);

  const emailLower = email.toLowerCase().trim();
  const raw        = await env.MEMBERS_KV.get(`user:${emailLower}`);
  if (!raw) return jsonResp({ error: 'Invalid email or password.' }, 401);

  const user = JSON.parse(raw);
  const hash = await hashPassword(password, user.salt);
  if (hash !== user.passwordHash)
    return jsonResp({ error: 'Invalid email or password.' }, 401);

  // Only after the password verifies, so this is not a second enumeration
  // oracle: you must already hold the credentials to learn the account exists.
  if (!isApproved(user) && !isAdminEmail(emailLower, env))
    return jsonResp({
      error: 'Your account is still awaiting approval from the church office. ' +
             'If it was just approved, please try again in a minute.',
    }, 403);

  const token = crypto.randomUUID();
  await env.MEMBERS_KV.put(
    `session:${token}`,
    JSON.stringify({ email: emailLower, name: user.name }),
    { expirationTtl: SESSION_TTL }
  );
  return jsonResp({ ok: true }, 200, { 'Set-Cookie': cookieHeader(token) });
}

async function handleLogout(request, env) {
  const token = getSessionToken(request);
  if (token) await env.MEMBERS_KV.delete(`session:${token}`);
  return redirectTo('/', { 'Set-Cookie': cookieHeader('', 0) });
}

async function handleSessionCheck(request, env) {
  const auth = await requireSession(request, env);
  if (!auth) return jsonResp({ authenticated: false }, 401);
  // isAdmin is for showing/hiding UI only — every admin route re-checks server-side.
  return jsonResp({ authenticated: true, name: auth.session.name, isAdmin: auth.isAdmin });
}

// ── Directory handlers ──────────────────────────────────────────────────────

/**
 * Returns the stored JSON string verbatim — no parse/stringify round trip, which
 * keeps a ~1 MB payload well inside the Free plan's 10 ms CPU budget.
 */
async function handleDirectory(request, env) {
  if (!(await requireSession(request, env)))
    return jsonResp({ error: 'Not authorised.' }, 403);

  const raw = await env.MEMBERS_KV.get('directory:data');
  if (!raw)
    return jsonResp({ columns: [], rows: [], nameColumns: [], searchColumns: [] });

  return new Response(raw, {
    headers: { 'Content-Type': 'application/json', ...NO_CACHE },
  });
}

async function handleDirectoryMeta(request, env) {
  if (!(await requireAdmin(request, env)))
    return jsonResp({ error: 'Not authorised.' }, 403);
  const raw = await env.MEMBERS_KV.get('directory:meta');
  return raw
    ? new Response(raw, { headers: { 'Content-Type': 'application/json', ...NO_CACHE } })
    : jsonResp({});
}

/**
 * The browser has already parsed and projected the CSV, so this validates shape
 * rather than re-parsing. Trusting the client's parse is acceptable because the
 * trust boundary is the authenticated admin — who confirms against an on-screen
 * preview — not the parser. The size caps are tripwires for the "one KV value
 * holds the whole directory" assumption.
 */
async function handleDirectoryImport(request, env) {
  const auth = await requireAdmin(request, env);
  if (!auth) return jsonResp({ error: 'Not authorised.' }, 403);

  let body;
  try { body = await request.json(); }
  catch { return jsonResp({ error: 'Invalid request body.' }, 400); }

  const { columns, rows, nameColumns, searchColumns } = body;

  if (!Array.isArray(columns) || !columns.length)
    return jsonResp({ error: 'No columns supplied.' }, 400);
  if (!Array.isArray(rows))
    return jsonResp({ error: 'No rows supplied.' }, 400);
  if (rows.length > MAX_DIRECTORY_ROWS)
    return jsonResp({ error: `Too many rows (limit ${MAX_DIRECTORY_ROWS}).` }, 413);
  if (!columns.every(c => typeof c === 'string'))
    return jsonResp({ error: 'Column headings must be text.' }, 400);

  const width = columns.length;
  for (const row of rows) {
    if (!Array.isArray(row) || row.length !== width)
      return jsonResp({ error: 'Every row must have one value per column.' }, 400);
    if (!row.every(cell => typeof cell === 'string'))
      return jsonResp({ error: 'Every value must be text.' }, 400);
  }

  const inRange = v => Number.isInteger(v) && v >= 0 && v < width;
  const names   = Array.isArray(nameColumns)   ? nameColumns.filter(inRange)   : [];
  const search  = Array.isArray(searchColumns) ? searchColumns.filter(inRange) : [];
  if (!names.length)
    return jsonResp({ error: 'At least one name column is required.' }, 400);

  const payload = JSON.stringify({
    columns, rows,
    nameColumns: names,
    searchColumns: search.length ? search : columns.map((_, i) => i),
    importedAt: new Date().toISOString(),
  });

  if (payload.length > MAX_DIRECTORY_BYTES)
    return jsonResp({ error: 'That export is too large. Please publish fewer columns.' }, 413);

  await env.MEMBERS_KV.put('directory:data', payload);
  await env.MEMBERS_KV.put('directory:meta', JSON.stringify({
    importedAt: new Date().toISOString(),
    importedBy: auth.session.email,
    columns,
    rowCount: rows.length,
  }));

  return jsonResp({ ok: true, rowCount: rows.length });
}

// ── Admin: approval queue ───────────────────────────────────────────────────

async function handleAdminUsers(request, env) {
  if (!(await requireAdmin(request, env)))
    return jsonResp({ error: 'Not authorised.' }, 403);

  const pending = [];
  let cursor;
  // list() returns at most 1000 keys per call, so page until it says otherwise.
  do {
    const page = await env.MEMBERS_KV.list({ prefix: 'pending:', cursor });
    for (const key of page.keys) {
      const meta  = key.metadata || {};
      const email = meta.email || key.name.slice('pending:'.length);
      // Admins are approved by virtue of ADMIN_EMAILS, so a leftover index key
      // from before they were listed shouldn't show up as awaiting approval.
      if (isAdminEmail(email, env)) continue;
      pending.push({ email, name: meta.name || '', createdAt: meta.createdAt || null });
    }
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);

  // list() can lag a minute behind an approve or deny, so check each account
  // itself: one that is gone (denied) or no longer pending (approved) is done.
  const records = await Promise.all(pending.map(p => env.MEMBERS_KV.get(`user:${p.email}`)));
  const stillPending = pending.filter((p, i) => {
    try { return JSON.parse(records[i]).status === 'pending'; } catch { return false; }
  });

  stillPending.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
  return jsonResp({ pending: stillPending });
}

async function handleAdminUserAction(request, env, action) {
  const auth = await requireAdmin(request, env);
  if (!auth) return jsonResp({ error: 'Not authorised.' }, 403);

  let body;
  try { body = await request.json(); }
  catch { return jsonResp({ error: 'Invalid request body.' }, 400); }

  const email = String(body.email || '').toLowerCase().trim();
  if (!email) return jsonResp({ error: 'Email is required.' }, 400);

  const raw = await env.MEMBERS_KV.get(`user:${email}`);
  if (!raw) {
    await env.MEMBERS_KV.delete(`pending:${email}`);   // clear an orphaned index key
    return jsonResp({ error: 'No such account.' }, 404);
  }

  if (action === 'approve') {
    const user = JSON.parse(raw);
    user.status     = 'approved';
    user.approvedAt = new Date().toISOString();
    user.approvedBy = auth.session.email;
    await env.MEMBERS_KV.put(`user:${email}`, JSON.stringify(user));
    await env.MEMBERS_KV.delete(`pending:${email}`);
    return jsonResp({ ok: true, status: 'approved' });
  }

  // Deny removes BOTH keys. Leaving user: behind would strand an account that
  // can never be approved and whose email can never be re-registered.
  await env.MEMBERS_KV.delete(`pending:${email}`);
  await env.MEMBERS_KV.delete(`user:${email}`);
  return jsonResp({ ok: true, status: 'denied' });
}

// ── Sermons (YouTube feed) ──────────────────────────────────────────────────

function decodeXml(str) {
  return str
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g,          (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

/** Bucket a video by its title; the buckets match the filter buttons on /sermons. */
function sermonCategory(title) {
  if (/sunday morning/i.test(title)) return 'Sunday Morning';
  if (/sunday evening/i.test(title)) return 'Sunday Evening';
  if (/wednesday/i.test(title))      return 'Wednesday';
  if (/special/i.test(title))        return 'Special';
  return 'Lessons';
}

const MONTHS = ['january','february','march','april','may','june','july',
                'august','september','october','november','december'];
// "October 4, 2026" / "September 20th, 2026" at the start of a title or description
const LEADING_DATE = /^\s*([a-z]+)\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})[\s,:–-]*/i;

/** Service date as YYYY-MM-DD from a leading "Month D, YYYY", or null. */
function leadingDate(text) {
  const m = text.match(LEADING_DATE);
  const month = m && MONTHS.indexOf(m[1].toLowerCase());
  if (!m || month < 0) return null;
  return `${m[3]}-${String(month + 1).padStart(2, '0')}-${m[2].padStart(2, '0')}`;
}

/**
 * Only <entry> blocks are read — the feed's first <title> is the channel name.
 * Videos are uploaded after the service (a Sunday evening service lands on
 * Monday), so the date comes from the title or description when either starts
 * with one, and the upload time is only the fallback.
 */
function parseYouTubeFeed(xml) {
  const tag = (block, name) => {
    const m = block.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`));
    return m ? decodeXml(m[1].trim()) : '';
  };
  return (xml.match(/<entry>[\s\S]*?<\/entry>/g) || [])
    .map(entry => {
      const rawTitle    = tag(entry, 'title');
      const description = tag(entry, 'media:description');
      const published   = tag(entry, 'published');
      const isDated     = LEADING_DATE.test(rawTitle) && leadingDate(rawTitle);
      return {
        videoId:     tag(entry, 'yt:videoId'),
        title:       (isDated && rawTitle.replace(LEADING_DATE, '').trim()) || rawTitle,
        date:        leadingDate(rawTitle) || leadingDate(description) || published.slice(0, 10),
        category:    sermonCategory(rawTitle),
        description: description === rawTitle ? '' : description.slice(0, 200),
      };
    })
    .filter(v => /^[\w-]{6,20}$/.test(v.videoId));
}

async function handleSermons(env) {
  let cached = null;
  try { cached = JSON.parse(await env.MEMBERS_KV.get(SERMON_CACHE_KEY)); } catch {}

  const send = data => jsonResp({ videos: data.videos, fetchedAt: data.fetchedAt }, 200,
                                { 'Cache-Control': 'public, max-age=300' });

  if (cached && Date.now() - cached.fetchedAt < SERMON_CACHE_TTL) return send(cached);

  try {
    const res = await fetch(YT_FEED_URL);
    if (!res.ok) throw new Error(`feed ${res.status}`);
    const videos = parseYouTubeFeed(await res.text());
    if (!videos.length) throw new Error('feed had no entries');
    const fresh = { fetchedAt: Date.now(), videos };
    await env.MEMBERS_KV.put(SERMON_CACHE_KEY, JSON.stringify(fresh));
    return send(fresh);
  } catch (err) {
    if (cached) return send(cached);
    return jsonResp({ error: 'Sermons are temporarily unavailable.' }, 502);
  }
}

/**
 * Read the channel's /live page. YouTube sends it to *some* video even when
 * nothing is on — the current stream, the next scheduled one, or a stale
 * scheduled stream that never ran (ours points at one from Dec 2024) — so the
 * page's own flags decide: liveBroadcastDetails.isLiveNow for live, and
 * isUpcoming plus a start time in the next few hours for upcoming.
 */
function parseLivePage(html, nowSec = Date.now() / 1000) {
  const offline = { status: 'offline' };
  const id = (html.match(/<link rel="canonical" href="https:\/\/www\.youtube\.com\/watch\?v=([\w-]{6,20})"/) || [])[1];
  if (!id) return offline;

  const details = (html.match(/"liveBroadcastDetails":(\{[^{}]*\})/) || [])[1];
  let broadcast = {};
  try { broadcast = JSON.parse(details); } catch {}

  let title = '';
  const t = html.match(/"videoDetails":\{"videoId":"[\w-]+","title":("(?:[^"\\]|\\.)*")/);
  try { title = t ? JSON.parse(t[1]) : ''; } catch {}

  if (broadcast.isLiveNow === true) return { status: 'live', videoId: id, title };

  const start = Number((html.match(/"scheduledStartTime":"(\d+)"/) || [])[1]);
  if (/"isUpcoming":true/.test(html) && start > nowSec && start - nowSec < UPCOMING_WINDOW)
    return { status: 'upcoming', videoId: id, title, startsAt: new Date(start * 1000).toISOString() };

  return offline;
}

// Kept per isolate rather than in KV: checking every minute would blow through
// KV's daily write allowance, and a cold isolate refetching costs nothing.
let liveCache = null;

async function handleLive() {
  const send = data => jsonResp(data, 200, { 'Cache-Control': 'public, max-age=60' });
  if (liveCache && Date.now() - liveCache.at < LIVE_CACHE_TTL) return send(liveCache.data);

  try {
    const res = await fetch(YT_LIVE_URL, { headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36',
      'Accept-Language': 'en-US,en;q=0.9',
      'Cookie': 'SOCS=CAI',   // skip the EU cookie-consent interstitial
    } });
    if (!res.ok) throw new Error(`live page ${res.status}`);
    const html = await res.text();
    const data = parseLivePage(html);
    // Shows up in `wrangler tail`; a page with no canonical video usually means a consent or bot-check page
    if (!/rel="canonical" href="https:\/\/www\.youtube\.com\/watch/.test(html))
      console.warn('live: YouTube page had no video', res.url, html.length);
    liveCache = { at: Date.now(), data };
    return send(data);
  } catch (err) {
    console.warn('live: check failed', String(err));
    return send(liveCache ? liveCache.data : { status: 'offline' });
  }
}

// ── Main fetch handler ──────────────────────────────────────────────────────

/** Treat /x, /x/ and /x.html as the same route. */
function normalizePath(path) {
  let p = path.replace(/\.html$/, '');
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
  return p || '/';
}

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = normalizePath(url.pathname);
    const method = request.method;

    // ── API routes ────────────────────────────────────────────────────────
    if (path.startsWith('/api/')) {
      // One admin POST can replace the whole roster, so verify the Origin on
      // top of SameSite=Strict.
      if (method === 'POST' && !sameOrigin(request))
        return jsonResp({ error: 'Bad origin.' }, 403);

      if (path === '/api/register' && method === 'POST') return handleRegister(request, env);
      if (path === '/api/login'    && method === 'POST') return handleLogin(request, env);
      if (path === '/api/logout')                        return handleLogout(request, env);
      if (path === '/api/session')                       return handleSessionCheck(request, env);
      if (path === '/api/directory' && method === 'GET') return handleDirectory(request, env);
      if (path === '/api/sermons'   && method === 'GET') return handleSermons(env);
      if (path === '/api/live'      && method === 'GET') return handleLive();

      if (path === '/api/admin/users' && method === 'GET')
        return handleAdminUsers(request, env);
      if (path === '/api/admin/users/approve' && method === 'POST')
        return handleAdminUserAction(request, env, 'approve');
      if (path === '/api/admin/users/deny' && method === 'POST')
        return handleAdminUserAction(request, env, 'deny');
      if (path === '/api/admin/directory/meta' && method === 'GET')
        return handleDirectoryMeta(request, env);
      if (path === '/api/admin/directory/import' && method === 'POST')
        return handleDirectoryImport(request, env);

      return jsonResp({ error: 'Not found.' }, 404);
    }

    // ── Members-only pages ────────────────────────────────────────────────
    // Every page here is built in this Worker and is NOT a file in the asset
    // store. The catch-all at the end of this block is load-bearing: it stops
    // any future file under /members from being served by the asset layer
    // without an auth check (the bypass fixed in commit f708fbe).
    if (path === '/members' || path.startsWith('/members/')) {
      const auth = await requireSession(request, env);
      if (!auth) return redirectTo('/login');

      if (path === '/members')
        return htmlResp(buildMembersPage(auth.session.name, auth.isAdmin));

      if (path === '/members/directory')
        return htmlResp(buildDirectoryPage());

      if (path === '/members/admin') {
        if (!auth.isAdmin) return redirectTo('/members');
        return htmlResp(buildAdminPage());
      }

      return htmlResp(
        renderPage({
          title: 'Not Found',
          activeNav: 'members',
          bodyHtml: `${portalHero({
            label: 'Members Only',
            heading: 'Page Not Found',
            sub: "That members page doesn't exist.",
            extraActions: '            <a href="/members" class="btn btn-outline">Back to Portal</a>\n',
          })}`,
        }),
        404
      );
    }

    // Redirect already-authenticated users away from login/register
    if (path === '/login' || path === '/register') {
      if (await requireSession(request, env)) return redirectTo('/members');
    }

    // Everything else: static assets
    return env.ASSETS.fetch(request);
  },
};
