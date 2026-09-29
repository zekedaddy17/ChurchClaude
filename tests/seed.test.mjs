/**
 * The staging seed script writes raw JSON straight into KV, bypassing every
 * code path that normally produces those records. So verify the records it
 * emits are ones the Worker actually accepts: the accounts must log in, the
 * pending ones must be refused and appear in the admin queue, and the seeded
 * directory must render.
 */
import worker from '../worker.js';
import { buildEntries, STAGING_PASSWORD } from '../scripts/seed-staging.mjs';

class KV {
  constructor() { this.store = new Map(); }
  async get(k) { const e = this.store.get(k); return e ? e.value : null; }
  async put(k, v, o = {}) { this.store.set(k, { value: v, metadata: o.metadata || null }); }
  async delete(k) { this.store.delete(k); }
  async list({ prefix = '' } = {}) {
    return { keys: [...this.store.keys()].filter(k => k.startsWith(prefix))
               .map(name => ({ name, metadata: this.store.get(name).metadata })),
             list_complete: true };
  }
}

const ORIGIN = 'https://cpcofc-test.workers.dev';
const kv = new KV();
const env = { MEMBERS_KV: kv, ADMIN_EMAILS: 'office@example.com',
              ASSETS: { fetch: async () => new Response('asset') } };

// Load exactly what the script would push to KV.
for (const e of await buildEntries()) {
  await kv.put(e.key, e.value, e.metadata ? { metadata: JSON.parse(e.metadata) } : {});
}

let pass = 0, fail = 0;
const check = (n, c, d = '') => c ? (pass++, console.log(`  ok   ${n}`))
                                  : (fail++, console.log(`  FAIL ${n}${d ? ' — ' + d : ''}`));

const hit = (path, opts = {}) => worker.fetch(new Request(ORIGIN + path, {
  method: opts.method || 'GET',
  headers: { ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
             ...(opts.cookie ? { Cookie: opts.cookie } : {}),
             ...(opts.method === 'POST' ? { Origin: ORIGIN } : {}) },
  body: opts.body ? JSON.stringify(opts.body) : undefined,
  redirect: 'manual',
}), env);

const login = (email) => hit('/api/login', { method: 'POST', body: { email, password: STAGING_PASSWORD } });
const cookieOf = (r) => (r.headers.get('Set-Cookie') || '').match(/session=([^;]+)/)?.[0] || null;

const admin = await login('office@example.com');
check('seeded admin can log in with the documented password', admin.status === 200, `got ${admin.status}`);
const adminCk = cookieOf(admin);
check('seeded admin reaches the admin page', (await hit('/members/admin', { cookie: adminCk })).status === 200);

const member = await login('member@example.com');
check('seeded approved member can log in', member.status === 200, `got ${member.status}`);
const memberCk = cookieOf(member);
check('seeded member reaches the directory', (await hit('/members/directory', { cookie: memberCk })).status === 200);
check('seeded member is NOT an admin', (await hit('/members/admin', { cookie: memberCk })).status === 302);

check('seeded pending account is refused at login', (await login('hopeful@example.com')).status === 403);

const q = await (await hit('/api/admin/users', { cookie: adminCk })).json();
check('both pending accounts show in the queue', q.pending.length === 2, JSON.stringify(q.pending));
check('queue entries carry names (metadata survived the round trip)',
      q.pending.every(p => p.name), JSON.stringify(q.pending));

const dir = await (await hit('/api/directory', { cookie: memberCk })).json();
check('seeded directory parses and has rows', dir.rows.length === 8, `got ${dir.rows?.length}`);
check('every row matches the column count', dir.rows.every(r => r.length === dir.columns.length));
check('name columns are in range',
      dir.nameColumns.every(i => i >= 0 && i < dir.columns.length));
check('accented characters survive', dir.rows.some(r => r[0] === 'José'));

// Approving a seeded pending account must work end to end.
await hit('/api/admin/users/approve', { method: 'POST', cookie: adminCk, body: { email: 'hopeful@example.com' } });
check('a seeded pending account can be approved and then log in',
      (await login('hopeful@example.com')).status === 200);

check('seed uses only example.com addresses',
      (await buildEntries()).filter(e => e.key.startsWith('user:'))
        .every(e => e.key.endsWith('@example.com')));

console.log(`\n  ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
