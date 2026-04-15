/**
 * Chase Park Church of Christ — Cloudflare Worker
 *
 * Routes:
 *   POST /api/register  — create member account (KV)
 *   POST /api/login     — verify credentials, issue session cookie
 *   GET  /api/logout    — clear session, redirect home
 *   GET  /api/session   — return current session info (for client-side checks)
 *   GET  /members       — auth-gated portal (redirect to /login if no session)
 *   GET  /members.html  — same as above
 *   *                   — fall through to static assets
 *
 * members.html is excluded from the asset store (.assetsignore) so the asset
 * layer can NEVER serve it directly, bypassing this auth check.
 */

const SESSION_TTL  = 60 * 60 * 24 * 7;   // 7 days in seconds
const PBKDF2_ITERS = 100_000;

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

function getSessionToken(request) {
  const match = (request.headers.get('Cookie') || '')
    .match(/(?:^|;\s*)session=([^;]+)/);
  return match ? match[1] : null;
}

function cookieHeader(token, maxAge = SESSION_TTL) {
  return `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

// ── Session helpers ─────────────────────────────────────────────────────────

async function getSession(request, env) {
  const token = getSessionToken(request);
  if (!token) return null;
  const raw = await env.MEMBERS_KV.get(`session:${token}`);
  return raw ? JSON.parse(raw) : null;
}

// ── Response helpers ────────────────────────────────────────────────────────

const NO_CACHE = { 'Cache-Control': 'no-store, no-cache, private' };

function jsonResp(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...NO_CACHE, ...extraHeaders },
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
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Handlers ────────────────────────────────────────────────────────────────

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
  if (await env.MEMBERS_KV.get(`user:${emailLower}`))
    return jsonResp({ error: 'An account with that email already exists.' }, 409);

  const salt         = await newSalt();
  const passwordHash = await hashPassword(password, salt);
  await env.MEMBERS_KV.put(`user:${emailLower}`, JSON.stringify({
    name: name.trim(), email: emailLower, passwordHash, salt,
    createdAt: new Date().toISOString(),
  }));
  return jsonResp({ ok: true });
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
  const session = await getSession(request, env);
  if (!session) return jsonResp({ authenticated: false }, 401);
  return jsonResp({ authenticated: true, name: session.name });
}

// ── Protected members page (inlined — NOT in asset store) ───────────────────

function buildMembersPage(memberName) {
  const name = escapeHtml(memberName);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Members Portal — Chase Park Church of Christ</title>
  <meta name="description" content="Members-only portal for Chase Park Church of Christ." />
  <meta name="robots" content="noindex, nofollow" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Lato:wght@300;400;700&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/css/style.css" />
</head>
<body>
  <header class="site-header">
    <nav class="nav-inner" aria-label="Main navigation">
      <a href="/" class="nav-logo" aria-label="Chase Park Church of Christ — Home">
        <span class="name">Chase Park</span>
        <span class="sub">Church of Christ</span>
      </a>
      <ul class="nav-links" role="list">
        <li><a href="/">Home</a></li>
        <li><a href="/about">About</a></li>
        <li><a href="/sermons">Sermons</a></li>
        <li><a href="/members" class="active">Members</a></li>
        <li><a href="/contact" class="nav-cta">Visit Us</a></li>
      </ul>
      <button class="nav-toggle" id="nav-toggle" aria-label="Open menu" aria-expanded="false" aria-controls="nav-mobile">
        <span></span><span></span><span></span>
      </button>
    </nav>
  </header>
  <nav class="nav-mobile" id="nav-mobile" aria-label="Mobile navigation">
    <a href="/">Home</a>
    <a href="/about">About</a>
    <a href="/sermons">Sermons</a>
    <a href="/members" class="active">Members</a>
    <a href="/contact">Visit Us</a>
  </nav>
  <main>
    <section class="page-hero" aria-labelledby="page-heading">
      <div class="container">
        <div class="page-hero-content portal-hero-content">
          <span class="section-label">Members Only</span>
          <h1 id="page-heading">Welcome, ${name}</h1>
          <p class="portal-hero-sub">You're signed in to the Chase Park members portal.</p>
          <div class="portal-hero-actions">
            <a href="/api/logout" class="btn btn-outline">Sign Out</a>
          </div>
        </div>
      </div>
    </section>
    <section class="section">
      <div class="container">
        <div class="section-header reveal">
          <span class="section-label">Resources</span>
          <h2>Member Resources</h2>
          <p>Everything you need to stay connected and informed as part of our church family.</p>
        </div>
        <div class="portal-grid">
          <div class="portal-card reveal">
            <div class="portal-card-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
            </div>
            <h3>Weekly Bulletin</h3>
            <p>The current week's bulletin with announcements, schedule updates, and congregational news.</p>
            <a href="#" class="portal-card-link">View Bulletin <svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a>
          </div>
          <div class="portal-card reveal">
            <div class="portal-card-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07A19.5 19.5 0 0 1 4.69 12 19.79 19.79 0 0 1 1.61 3.4 2 2 0 0 1 3.6 1.22h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L7.91 8.82a16 16 0 0 0 6.29 6.29l.95-.95a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
            </div>
            <h3>Newsline</h3>
            <p>Member announcements, prayer requests, celebrations, and important congregational updates.</p>
            <a href="#" class="portal-card-link">Read Newsline <svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a>
          </div>
          <div class="portal-card reveal">
            <div class="portal-card-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
            </div>
            <h3>Church Calendar</h3>
            <p>Full schedule of upcoming services, classes, events, fellowships, and ministry activities.</p>
            <a href="#" class="portal-card-link">View Calendar <svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a>
          </div>
          <div class="portal-card reveal">
            <div class="portal-card-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>
            </div>
            <h3>Prayer List</h3>
            <p>Current prayer requests from congregation members. Pray for one another and submit your own requests.</p>
            <a href="#" class="portal-card-link">View Requests <svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a>
          </div>
          <div class="portal-card reveal">
            <div class="portal-card-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
            </div>
            <h3>Member Directory</h3>
            <p>Contact information for members who have opted in. Stay connected with your church family.</p>
            <a href="#" class="portal-card-link">View Directory <svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a>
          </div>
          <div class="portal-card reveal">
            <div class="portal-card-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg>
            </div>
            <h3>Bible Study Materials</h3>
            <p>Class notes, study guides, and handouts from Sunday and Wednesday Bible classes.</p>
            <a href="#" class="portal-card-link">View Materials <svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7"/></svg></a>
          </div>
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
    </section>
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
</body>
</html>`;
}

// ── Main fetch handler ──────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    // API routes
    if (path === '/api/register' && method === 'POST') return handleRegister(request, env);
    if (path === '/api/login'    && method === 'POST') return handleLogin(request, env);
    if (path === '/api/logout')                        return handleLogout(request, env);
    if (path === '/api/session')                       return handleSessionCheck(request, env);

    // Protected members portal — built dynamically, NOT from asset store
    if (path === '/members' || path === '/members.html') {
      const session = await getSession(request, env);
      if (!session) return redirectTo('/login');
      return new Response(buildMembersPage(session.name), {
        status: 200,
        headers: { 'Content-Type': 'text/html;charset=UTF-8', ...NO_CACHE },
      });
    }

    // Redirect already-authenticated users away from login/register
    if (path === '/login'    || path === '/login.html' ||
        path === '/register' || path === '/register.html') {
      const session = await getSession(request, env);
      if (session) return redirectTo('/members');
    }

    // Everything else: static assets
    return env.ASSETS.fetch(request);
  },
};
