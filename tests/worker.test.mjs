import worker from '../worker.js';

// ── KV mock modelling the bits this Worker depends on ──────────────────────
class KV {
  constructor() { this.store = new Map(); }
  async get(key) { const e = this.store.get(key); return e ? e.value : null; }
  async put(key, value, opts = {}) {
    this.store.set(key, { value, metadata: opts.metadata || null });
  }
  async delete(key) { this.store.delete(key); }
  async list({ prefix = '', cursor, limit = 1000 } = {}) {
    const all = [...this.store.entries()]
      .filter(([k]) => k.startsWith(prefix))
      .sort(([a], [b]) => a.localeCompare(b));
    const start = cursor ? parseInt(cursor, 10) : 0;
    const page  = all.slice(start, start + limit);
    const end   = start + page.length;
    return {
      keys: page.map(([name, e]) => ({ name, metadata: e.metadata })),
      list_complete: end >= all.length,
      cursor: end >= all.length ? undefined : String(end),
    };
  }
}

const ORIGIN = 'https://cpcofc.test';
let kv, env;
function reset(adminEmails = 'admin@chasepark.test') {
  kv  = new KV();
  env = {
    MEMBERS_KV: kv,
    ADMIN_EMAILS: adminEmails,
    ASSETS: { fetch: async (req) => new Response('ASSET:' + new URL(req.url).pathname, { status: 200 }) },
  };
}

function req(path, { method = 'GET', body, cookie, origin } = {}) {
  const headers = {};
  if (body)   headers['Content-Type'] = 'application/json';
  if (cookie) headers['Cookie'] = cookie;
  if (origin !== undefined) headers['Origin'] = origin;
  else if (method === 'POST') headers['Origin'] = ORIGIN;
  return new Request(ORIGIN + path, {
    method, headers,
    body: body ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  });
}
const hit = (path, opts) => worker.fetch(req(path, opts), env);

function cookieFrom(res) {
  const sc = res.headers.get('Set-Cookie') || '';
  const m = sc.match(/session=([^;]+)/);
  return m ? 'session=' + m[1] : null;
}

// ── Tiny assertion harness ─────────────────────────────────────────────────
let pass = 0, fail = 0;
const results = [];
function check(name, cond, detail = '') {
  if (cond) { pass++; results.push(`  ok   ${name}`); }
  else { fail++; results.push(`  FAIL ${name}${detail ? ' — ' + detail : ''}`); }
}
function section(t) { results.push(`\n── ${t} `.padEnd(70, '─')); }

async function register(email, name = 'Test User', password = 'password123') {
  return hit('/api/register', { method: 'POST', body: { name, email, password } });
}
async function login(email, password = 'password123') {
  return hit('/api/login', { method: 'POST', body: { email, password } });
}

// ═══════════════════════════════════════════════════════════════════════════
section('Grandfathering: pre-existing account with no status field');
{
  reset();
  // Exactly the old record shape, written before the approval queue existed.
  const salt = 'a'.repeat(32);
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode('password123'), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: Uint8Array.from(salt.match(/../g).map(h => parseInt(h, 16))), iterations: 100000, hash: 'SHA-256' },
    key, 256);
  const hash = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
  await kv.put('user:old@member.test', JSON.stringify({
    name: 'Old Member', email: 'old@member.test', passwordHash: hash, salt,
    createdAt: '2025-01-01T00:00:00.000Z',
  }));

  const res = await login('old@member.test');
  check('legacy account (no status) can still log in', res.status === 200, `got ${res.status}`);
  const ck = cookieFrom(res);
  const portal = await hit('/members', { cookie: ck });
  check('legacy account reaches /members', portal.status === 200, `got ${portal.status}`);
}

section('Approval queue');
{
  reset();
  const r = await register('new@member.test', 'New Member');
  const rBody = await r.json();
  check('registration returns ok', r.status === 200 && rBody.ok === true);
  check('registration does NOT confirm account creation',
        /submitted/i.test(rBody.message || ''), JSON.stringify(rBody));

  const l = await login('new@member.test');
  check('pending account cannot log in', l.status === 403, `got ${l.status}`);
  check('pending account gets no session cookie', cookieFrom(l) === null);
  const lb = await l.json();
  check('pending message explains approval', /approval/i.test(lb.error));

  const wrongPw = await login('new@member.test', 'wrongwrongwrong');
  const wb = await wrongPw.json();
  check('wrong password on pending account reveals nothing',
        wrongPw.status === 401 && /Invalid email or password/.test(wb.error),
        `${wrongPw.status} ${wb.error}`);

  check('pending index key written with metadata',
        kv.store.get('pending:new@member.test')?.metadata?.name === 'New Member');
}

section('Enumeration oracle');
{
  reset();
  const first  = await register('dupe@member.test');
  const second = await register('dupe@member.test');
  const b1 = await first.json(), b2 = await second.json();
  check('duplicate registration is indistinguishable from a fresh one',
        first.status === second.status && JSON.stringify(b1) === JSON.stringify(b2),
        `${first.status}/${second.status} ${JSON.stringify(b2)}`);
  check('duplicate registration did not overwrite the original record',
        JSON.parse(kv.store.get('user:dupe@member.test').value).name === 'Test User');
}

section('Admin bootstrap and privilege escalation');
{
  reset();
  const r = await register('admin@chasepark.test', 'Impostor');
  check('registering an ADMIN_EMAILS address is silently refused',
        r.status === 200 && kv.store.get('user:admin@chasepark.test') === undefined);

  // The real admin is pre-created (as the deploy runbook requires).
  await register('realadmin@chasepark.test', 'Real Admin');
  const u = JSON.parse(kv.store.get('user:realadmin@chasepark.test').value);
  u.status = 'approved';
  await kv.put('user:realadmin@chasepark.test', JSON.stringify(u));
  check('no role field is ever persisted on a user record', u.role === undefined);

  env.ADMIN_EMAILS = 'realadmin@chasepark.test';
  const res = await login('realadmin@chasepark.test');
  const adminCk = cookieFrom(res);
  const adminPage = await hit('/members/admin', { cookie: adminCk });
  check('admin reaches /members/admin', adminPage.status === 200, `got ${adminPage.status}`);

  // Revocation must bite immediately, not in 7 days when the session expires.
  env.ADMIN_EMAILS = '';
  const after = await hit('/members/admin', { cookie: adminCk });
  check('removing ADMIN_EMAILS revokes admin on the existing session',
        after.status === 302, `got ${after.status}`);
  const apiAfter = await hit('/api/admin/users', { cookie: adminCk });
  check('revoked admin is refused by the admin API', apiAfter.status === 403, `got ${apiAfter.status}`);
}

section('Auth gating matrix');
{
  reset();
  await register('member@test.test');
  const mu = JSON.parse(kv.store.get('user:member@test.test').value);
  mu.status = 'approved';
  await kv.put('user:member@test.test', JSON.stringify(mu));
  const memberCk = cookieFrom(await login('member@test.test'));

  const gated = [
    ['/members', 'GET'],
    ['/members/directory', 'GET'],
    ['/members/admin', 'GET'],
    ['/api/directory', 'GET'],
    ['/api/admin/users', 'GET'],
    ['/api/admin/directory/meta', 'GET'],
    ['/api/admin/directory/import', 'POST'],
    ['/api/admin/users/approve', 'POST'],
    ['/api/admin/users/deny', 'POST'],
  ];

  for (const [p, method] of gated) {
    const res = await hit(p, { method, body: method === 'POST' ? {} : undefined });
    const txt = res.status < 300 ? await res.clone().text() : '';
    check(`anon ${method} ${p} is refused`,
          res.status === 302 || res.status === 401 || res.status === 403,
          `got ${res.status} ${txt.slice(0, 60)}`);
  }

  const adminOnly = [
    ['/members/admin', 'GET'],
    ['/api/admin/users', 'GET'],
    ['/api/admin/directory/meta', 'GET'],
    ['/api/admin/directory/import', 'POST'],
    ['/api/admin/users/approve', 'POST'],
    ['/api/admin/users/deny', 'POST'],
  ];
  for (const [p, method] of adminOnly) {
    const res = await hit(p, { method, cookie: memberCk, body: method === 'POST' ? {} : undefined });
    check(`non-admin member ${method} ${p} is refused`,
          res.status === 302 || res.status === 403, `got ${res.status}`);
  }

  check('approved member CAN reach /members/directory',
        (await hit('/members/directory', { cookie: memberCk })).status === 200);
  check('approved member CAN read /api/directory',
        (await hit('/api/directory', { cookie: memberCk })).status === 200);
}

section('Session revocation via denial');
{
  reset();
  await register('doomed@test.test');
  const du = JSON.parse(kv.store.get('user:doomed@test.test').value);
  du.status = 'approved';
  await kv.put('user:doomed@test.test', JSON.stringify(du));
  const ck = cookieFrom(await login('doomed@test.test'));
  check('approved member has access', (await hit('/members', { cookie: ck })).status === 200);

  await kv.delete('user:doomed@test.test');
  check('deleting the user record kills the live session immediately',
        (await hit('/members', { cookie: ck })).status === 302);
}

section('/members catch-all (asset-layer bypass guard)');
{
  reset();
  await register('m2@test.test');
  const u2 = JSON.parse(kv.store.get('user:m2@test.test').value);
  u2.status = 'approved';
  await kv.put('user:m2@test.test', JSON.stringify(u2));
  const ck = cookieFrom(await login('m2@test.test'));

  for (const p of ['/members/secret.html', '/members/anything', '/members/sub/dir/file.html']) {
    const res = await hit(p, { cookie: ck });
    const txt = await res.text();
    check(`${p} never reaches the asset store`,
          res.status === 404 && !txt.startsWith('ASSET:'), `got ${res.status} ${txt.slice(0, 40)}`);
  }
  const anon = await hit('/members/secret.html');
  check('/members/secret.html anonymously redirects, not asset-served', anon.status === 302);

  // Public pages must still be served normally.
  const pub = await hit('/about.html');
  check('public assets still served', (await pub.text()).startsWith('ASSET:'));
}

section('Path normalization');
{
  reset();
  await register('n@test.test');
  const nu = JSON.parse(kv.store.get('user:n@test.test').value);
  nu.status = 'approved';
  await kv.put('user:n@test.test', JSON.stringify(nu));
  const ck = cookieFrom(await login('n@test.test'));
  for (const p of ['/members', '/members/', '/members.html']) {
    check(`${p} resolves to the portal`, (await hit(p, { cookie: ck })).status === 200);
  }
  for (const p of ['/members/admin', '/members/admin/', '/members/admin.html']) {
    check(`${p} is admin-gated consistently`, (await hit(p, { cookie: ck })).status === 302);
  }
}

section('Cookie token validation');
{
  reset();
  for (const bad of ['session=' + 'A'.repeat(600), 'session=../../etc/passwd', 'session=not-a-uuid']) {
    const res = await hit('/members', { cookie: bad });
    check(`malformed cookie rejected cleanly (${bad.slice(0, 24)}…)`, res.status === 302, `got ${res.status}`);
  }
}

section('CSRF / Origin check');
{
  reset();
  const res = await hit('/api/login', {
    method: 'POST', origin: 'https://evil.example',
    body: { email: 'x@y.z', password: 'password123' },
  });
  check('cross-origin POST is rejected', res.status === 403, `got ${res.status}`);
}

section('Directory import');
{
  reset('boss@chasepark.test');
  await register('boss@chasepark.test');       // refused (admin email)
  // Pre-create the admin the supported way.
  env.ADMIN_EMAILS = '';
  await register('boss@chasepark.test', 'Boss');
  const bu = JSON.parse(kv.store.get('user:boss@chasepark.test').value);
  bu.status = 'approved';
  await kv.put('user:boss@chasepark.test', JSON.stringify(bu));
  const ck = cookieFrom(await login('boss@chasepark.test'));
  env.ADMIN_EMAILS = 'boss@chasepark.test';

  const good = {
    columns: ['First Name', 'Last Name', 'Email'],
    rows: [['Jo', 'Smith', 'jo@x.test'], ['Pat', 'Jones', 'pat@x.test']],
    nameColumns: [0, 1],
    searchColumns: [0, 1, 2],
  };
  const imp = await hit('/api/admin/directory/import', { method: 'POST', cookie: ck, body: good });
  const ib = await imp.json();
  check('valid import succeeds', imp.status === 200 && ib.rowCount === 2, JSON.stringify(ib));

  const bad = [
    ['ragged rows', { ...good, rows: [['a', 'b']] }],
    ['non-string cells', { ...good, rows: [['a', 'b', { evil: 1 }]] }],
    ['no columns', { ...good, columns: [] }],
    ['no name column', { ...good, nameColumns: [] }],
    ['out-of-range name index', { ...good, nameColumns: [99] }],
    ['too many rows', { ...good, rows: Array.from({ length: 5001 }, () => ['a', 'b', 'c']) }],
  ];
  for (const [label, payload] of bad) {
    const res = await hit('/api/admin/directory/import', { method: 'POST', cookie: ck, body: payload });
    check(`import rejects ${label}`, res.status >= 400, `got ${res.status}`);
  }

  // Confirm the good import is still intact after the rejected ones.
  const dir = await (await hit('/api/directory', { cookie: ck })).json();
  check('rejected imports did not corrupt stored data', dir.rows.length === 2);
  check('stored data carries importedAt', typeof dir.importedAt === 'string');

  const meta = await (await hit('/api/admin/directory/meta', { cookie: ck })).json();
  check('meta records who imported', meta.importedBy === 'boss@chasepark.test');
  check('meta records the row count', meta.rowCount === 2);

  // Re-import replaces rather than appends.
  await hit('/api/admin/directory/import', {
    method: 'POST', cookie: ck,
    body: { ...good, rows: [['Solo', 'Person', 's@x.test']] },
  });
  const dir2 = await (await hit('/api/directory', { cookie: ck })).json();
  check('re-import replaces rather than appends', dir2.rows.length === 1);
}

section('XSS payloads survive as inert data');
{
  reset('x@chasepark.test');
  env.ADMIN_EMAILS = '';                       // pre-create the admin, as the runbook requires
  await register('x@chasepark.test', 'X');
  const xu = JSON.parse(kv.store.get('user:x@chasepark.test').value);
  xu.status = 'approved';
  await kv.put('user:x@chasepark.test', JSON.stringify(xu));
  const ck = cookieFrom(await login('x@chasepark.test'));
  env.ADMIN_EMAILS = 'x@chasepark.test';

  const evil = '</script><script>alert(1)</script>';
  await hit('/api/admin/directory/import', {
    method: 'POST', cookie: ck,
    body: { columns: ['Name', 'Note'], rows: [[evil, '\'"><img onerror=1>']], nameColumns: [0], searchColumns: [0, 1] },
  });
  const page = await (await hit('/members/directory', { cookie: ck })).text();
  check('directory page never inlines row data into its HTML', !page.includes('alert(1)'));
  const api = await (await hit('/api/directory', { cookie: ck })).json();
  check('payload is preserved verbatim as data', api.rows[0][0] === evil);
}

section('Member name escaping on the portal page');
{
  reset();
  await register('esc@test.test', '<img src=x onerror=alert(1)>');
  const eu = JSON.parse(kv.store.get('user:esc@test.test').value);
  eu.status = 'approved';
  await kv.put('user:esc@test.test', JSON.stringify(eu));
  const ck = cookieFrom(await login('esc@test.test'));
  const html = await (await hit('/members', { cookie: ck })).text();
  check('member name is HTML-escaped in the hero',
        html.includes('&lt;img src=x onerror=alert(1)&gt;') && !html.includes('<img src=x'));
}

section('Approve / deny lifecycle');
{
  reset('a@chasepark.test');
  env.ADMIN_EMAILS = '';
  await register('a@chasepark.test', 'Admin');
  const au = JSON.parse(kv.store.get('user:a@chasepark.test').value);
  au.status = 'approved';
  await kv.put('user:a@chasepark.test', JSON.stringify(au));
  const ck = cookieFrom(await login('a@chasepark.test'));
  env.ADMIN_EMAILS = 'a@chasepark.test';

  await register('alice@test.test', 'Alice');
  await register('bob@test.test', 'Bob');

  const q = await (await hit('/api/admin/users', { cookie: ck })).json();
  check('queue lists both pending accounts', q.pending.length === 2, JSON.stringify(q.pending));
  check('queue entries carry names from KV metadata (no extra get())',
        q.pending.every(p => p.name));

  await hit('/api/admin/users/approve', { method: 'POST', cookie: ck, body: { email: 'alice@test.test' } });
  check('approved user can now log in', (await login('alice@test.test')).status === 200);
  check('approval clears the pending index key', !kv.store.has('pending:alice@test.test'));

  await hit('/api/admin/users/deny', { method: 'POST', cookie: ck, body: { email: 'bob@test.test' } });
  check('denial removes the user record', !kv.store.has('user:bob@test.test'));
  check('denial removes the pending index key', !kv.store.has('pending:bob@test.test'));
  const reReg = await register('bob@test.test', 'Bob Again');
  check('denied email can register again', kv.store.has('user:bob@test.test') && reReg.status === 200);

  const q2 = await (await hit('/api/admin/users', { cookie: ck })).json();
  check('queue reflects approve/deny', q2.pending.length === 1 && q2.pending[0].email === 'bob@test.test',
        JSON.stringify(q2.pending));
}

section('Queue pagination (cursor loop)');
{
  reset('p@chasepark.test');
  env.ADMIN_EMAILS = '';
  await register('p@chasepark.test', 'P');
  const pu = JSON.parse(kv.store.get('user:p@chasepark.test').value);
  pu.status = 'approved';
  await kv.put('user:p@chasepark.test', JSON.stringify(pu));
  const ck = cookieFrom(await login('p@chasepark.test'));
  env.ADMIN_EMAILS = 'p@chasepark.test';

  // Force multiple pages by shrinking the mock's page size below the key count.
  for (let i = 0; i < 25; i++) {
    await kv.put(`pending:u${String(i).padStart(3, '0')}@t.test`, '', {
      metadata: { name: 'U' + i, email: `u${String(i).padStart(3, '0')}@t.test`, createdAt: new Date(i * 1000).toISOString() },
    });
  }
  const origList = kv.list.bind(kv);
  kv.list = (opts) => origList({ ...opts, limit: 10 });   // 25 keys across 3 pages

  const q = await (await hit('/api/admin/users', { cookie: ck })).json();
  check('cursor loop collects every page', q.pending.length === 25, `got ${q.pending.length}`);
}

section('Admin bootstrap runbook (register → set ADMIN_EMAILS → sign in)');
{
  reset('');                                   // secret not set yet
  const r = await register('office@chasepark.test', 'Church Office');
  check('admin signs up through the normal form', r.status === 200);
  check('their account starts out pending',
        JSON.parse(kv.store.get('user:office@chasepark.test').value).status === 'pending');

  const before = await login('office@chasepark.test');
  check('pending, so cannot sign in yet', before.status === 403);

  env.ADMIN_EMAILS = 'office@chasepark.test';  // wrangler secret put ADMIN_EMAILS

  const after = await login('office@chasepark.test');
  check('sign-in works once ADMIN_EMAILS names them — no KV surgery needed',
        after.status === 200, `got ${after.status}`);
  const ck = cookieFrom(after);
  check('and they reach the admin page', (await hit('/members/admin', { cookie: ck })).status === 200);

  const q = await (await hit('/api/admin/users', { cookie: ck })).json();
  check('the admin does not appear in their own approval queue',
        q.pending.length === 0, JSON.stringify(q.pending));
}

console.log(results.join('\n'));
console.log(`\n${'═'.repeat(70)}\n  ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
