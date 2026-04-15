/**
 * Chase Park Church of Christ — Cloudflare Worker
 * Handles: member registration, login, logout, session-protected /members route.
 * All other requests fall through to static assets.
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
  const enc   = new TextEncoder();
  const key   = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits  = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBuf(saltHex), iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    key, 256
  );
  return bufToHex(bits);
}

async function newSalt() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return bufToHex(bytes.buffer);
}

// ── Cookie helpers ──────────────────────────────────────────────────────────

function getSessionToken(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match  = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  return match ? match[1] : null;
}

function setCookieHeader(token, maxAge = SESSION_TTL) {
  return `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

// ── Session helpers ─────────────────────────────────────────────────────────

async function getSession(request, env) {
  const token = getSessionToken(request);
  if (!token) return null;
  const raw = await env.MEMBERS_KV.get(`session:${token}`);
  return raw ? JSON.parse(raw) : null;
}

// ── JSON / redirect responses ───────────────────────────────────────────────

function jsonResp(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function redirectTo(url, headers = {}) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: url,
      'Cache-Control': 'no-store, no-cache, private',
      ...headers,
    },
  });
}

// ── Handlers ────────────────────────────────────────────────────────────────

async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResp({ error: 'Invalid request body.' }, 400); }

  const { name, email, password } = body;

  if (!name || !email || !password)
    return jsonResp({ error: 'All fields are required.' }, 400);

  if (password.length < 8)
    return jsonResp({ error: 'Password must be at least 8 characters.' }, 400);

  const emailLower = email.toLowerCase().trim();
  const existing   = await env.MEMBERS_KV.get(`user:${emailLower}`);
  if (existing)
    return jsonResp({ error: 'An account with that email already exists.' }, 409);

  const salt         = await newSalt();
  const passwordHash = await hashPassword(password, salt);

  await env.MEMBERS_KV.put(`user:${emailLower}`, JSON.stringify({
    name:   name.trim(),
    email:  emailLower,
    passwordHash,
    salt,
    createdAt: new Date().toISOString(),
  }));

  return jsonResp({ ok: true });
}

async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResp({ error: 'Invalid request body.' }, 400); }

  const { email, password } = body;
  if (!email || !password)
    return jsonResp({ error: 'Email and password are required.' }, 400);

  const emailLower = email.toLowerCase().trim();
  const raw        = await env.MEMBERS_KV.get(`user:${emailLower}`);
  if (!raw)
    return jsonResp({ error: 'Invalid email or password.' }, 401);

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

  return jsonResp({ ok: true }, 200, {
    'Set-Cookie': setCookieHeader(token),
  });
}

async function handleLogout(request, env) {
  const token = getSessionToken(request);
  if (token) await env.MEMBERS_KV.delete(`session:${token}`);
  return redirectTo('/', {
    'Set-Cookie': setCookieHeader('', 0),
  });
}

// ── Protected member page ───────────────────────────────────────────────────

async function serveMembersPage(request, env) {
  const session = await getSession(request, env);
  if (!session) return redirectTo('/login');

  // Fetch the static members.html from the asset store
  const assetReq  = new Request(new URL('/members.html', request.url).toString());
  const assetResp = await env.ASSETS.fetch(assetReq);
  if (!assetResp.ok) return assetResp;

  // Inject the member's name into the placeholder
  const html     = await assetResp.text();
  const injected = html.replace(/\{\{MEMBER_NAME\}\}/g, escapeHtml(session.name));

  return new Response(injected, {
    status: 200,
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'no-store, no-cache, private',
    },
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
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

    // Protected members area
    if (path === '/members' || path === '/members.html') return serveMembersPage(request, env);

    // Everything else: static assets
    return env.ASSETS.fetch(request);
  },
};
