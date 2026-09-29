/**
 * node --check worker.js cannot see inside a template literal, so a broken
 * escape in an inlined <script> ships silently. Render every members-only page
 * and syntax-check the JavaScript that actually reaches the browser.
 */
import worker from '../worker.js';
import { writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

class KV {
  constructor() { this.store = new Map(); }
  async get(k) { const e = this.store.get(k); return e ? e.value : null; }
  async put(k, v, o = {}) { this.store.set(k, { value: v, metadata: o.metadata || null }); }
  async delete(k) { this.store.delete(k); }
  async list({ prefix = '' } = {}) {
    return { keys: [...this.store.keys()].filter(k => k.startsWith(prefix)).map(name => ({ name, metadata: this.store.get(name).metadata })), list_complete: true };
  }
}

const kv = new KV();
const env = { MEMBERS_KV: kv, ADMIN_EMAILS: 'a@t.test',
              ASSETS: { fetch: async () => new Response('asset') } };

const salt = 'ab'.repeat(16);
const key  = await crypto.subtle.importKey('raw', new TextEncoder().encode('password123'), 'PBKDF2', false, ['deriveBits']);
const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2',
  salt: Uint8Array.from(salt.match(/../g).map(h => parseInt(h, 16))), iterations: 100000, hash: 'SHA-256' }, key, 256);
const passwordHash = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
await kv.put('user:a@t.test', JSON.stringify({ name: 'A', email: 'a@t.test', passwordHash, salt, status: 'approved' }));
await kv.put('session:00000000-0000-4000-8000-000000000000', JSON.stringify({ email: 'a@t.test', name: 'A' }));

const COOKIE = 'session=00000000-0000-4000-8000-000000000000';
let pass = 0, fail = 0;

for (const path of ['/members', '/members/directory', '/members/admin', '/members/nope']) {
  const res  = await worker.fetch(new Request('https://t.test' + path, { headers: { Cookie: COOKIE } }), env);
  const html = await res.text();

  // Structural sanity
  const opens = (html.match(/<script\b/g) || []).length;
  const closes = (html.match(/<\/script>/g) || []).length;
  if (opens !== closes) { console.log(`  FAIL ${path}: ${opens} <script> vs ${closes} </script>`); fail++; }
  else { pass++; }

  // Every inline script must parse.
  const blocks = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  blocks.forEach((code, i) => {
    const f = `/tmp/_cpcofc_chk${i}.js`;
    writeFileSync(f, code);
    try {
      execFileSync('node', ['--check', f], { stdio: 'pipe' });
      pass++;
    } catch (e) {
      fail++;
      console.log(`  FAIL ${path} inline script #${i}:\n${e.stderr.toString().split('\n').slice(0, 6).join('\n')}`);
    }
  });

  // A stray control character inside a script is the signature of a
  // mis-escaped sequence in the template literal that produced it.
  blocks.forEach((code, i) => {
    const bad = [...code].filter(c => c.charCodeAt(0) < 0x20 && !'\n\t'.includes(c));
    if (bad.length) { fail++; console.log(`  FAIL ${path} script #${i}: ${bad.length} raw control char(s)`); }
    else pass++;
  });

  console.log(`  ok   ${path} — ${blocks.length} inline script(s), ${html.length} bytes`);
}

console.log(`\n  ${pass} checks passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
