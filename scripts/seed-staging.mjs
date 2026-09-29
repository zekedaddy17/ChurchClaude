#!/usr/bin/env node
/**
 * Fill the STAGING KV namespace with throwaway accounts and a fake directory,
 * so the test site has something to look at.
 *
 *   node scripts/seed-staging.mjs --print   # show the commands, change nothing
 *   node scripts/seed-staging.mjs           # actually write to staging KV
 *
 * Refuses to run without --env test wiring, and every account it creates uses
 * an @example.com address with a throwaway password. Never point this at
 * production: it would overwrite real member accounts.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT  = join(dirname(fileURLToPath(import.meta.url)), '..');
const PRINT = process.argv.includes('--print');
const PASSWORD = 'staging-password';

/**
 * Refuse to run unless staging is wired up to its own namespace. The last check
 * is the important one: seeding production would overwrite real accounts.
 */
function assertStagingConfigured() {
  const toml = readFileSync(join(ROOT, 'wrangler.toml'), 'utf8');
  if (!/\[env\.test\]/.test(toml)) {
    console.error('wrangler.toml has no [env.test] section.');
    process.exit(1);
  }
  const testId = toml.split('[env.test]')[1]?.match(/id\s*=\s*"([^"]+)"/)?.[1];
  if (!testId || testId.startsWith('REPLACE_ME')) {
    console.error(
      'The staging KV namespace id is still a placeholder.\n' +
      'Run:  npx wrangler kv namespace create MEMBERS_KV_TEST\n' +
      'then put the printed id into [[env.test.kv_namespaces]] in wrangler.toml.');
    process.exit(1);
  }
  const prodId = toml.split('[env.test]')[0].match(/id\s*=\s*"([^"]+)"/)?.[1];
  if (prodId && testId === prodId) {
    console.error('REFUSING TO RUN: staging and production share a KV namespace id.');
    process.exit(1);
  }
}

// ── Same PBKDF2 parameters the Worker uses ────────────────────────────────
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

async function hash(password, saltHex) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: Uint8Array.from(saltHex.match(/../g).map(h => parseInt(h, 16))),
    iterations: 100_000, hash: 'SHA-256',
  }, key, 256));
}

async function user(email, name, status) {
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  return {
    key: `user:${email}`,
    value: JSON.stringify({
      name, email, salt, passwordHash: await hash(PASSWORD, salt),
      status, createdAt: new Date().toISOString(),
    }),
  };
}

const COLUMNS = ['First Name', 'Last Name', 'E-mail', 'Cell Phone', 'Address Line 1', 'City', 'State', 'Zip'];
const PEOPLE = [
  ['Ruth', 'Calloway', 'ruth.calloway@example.com', '(256) 555-0142', '1204 Maple Grove Dr', 'Huntsville', 'AL', '35811'],
  ['José', 'Núñez', 'jose.nunez@example.com', '(256) 555-0177', '88 Willow Bend Rd, Apt 3', 'Huntsville', 'AL', '35810'],
  ['Mary Ann', "O'Brien", 'maryann.obrien@example.com', '(256) 555-0198', '4417 Chase Park Cir', 'Huntsville', 'AL', '35811'],
  ['Thomas', 'Whitfield', 't.whitfield@example.com', '(256) 555-0110', '709 Winchester Rd NE', 'Huntsville', 'AL', '35811'],
  ['Deborah', 'Ainsworth', 'deb.ainsworth@example.com', '(256) 555-0164', '233 Sparkman Dr', 'Huntsville', 'AL', '35816'],
  ['Silas', 'Redmond', 'silas.redmond@example.com', '(256) 555-0135', '15 Monte Sano Blvd', 'Huntsville', 'AL', '35801'],
  ['Naomi', 'Fairweather', 'naomi.f@example.com', '(256) 555-0129', '902 Bankhead Pkwy', 'Huntsville', 'AL', '35801'],
  ['Ezekiel', 'Barrington', 'zeke.b@example.com', '(256) 555-0153', '3300 Triana Blvd SW', 'Huntsville', 'AL', '35805'],
];

export const STAGING_PASSWORD = PASSWORD;

export async function buildEntries() {
  const now = new Date().toISOString();
  const entries = [
    await user('office@example.com',   'Church Office',   'approved'),
    await user('member@example.com',   'Ruth Calloway',   'approved'),
    await user('hopeful@example.com',  'Daniel Ortiz',    'pending'),
    await user('newcomer@example.com', 'Priscilla Vance', 'pending'),
    {
      key: 'directory:data',
      value: JSON.stringify({
        columns: COLUMNS, rows: PEOPLE,
        nameColumns: [0, 1],
        searchColumns: COLUMNS.map((_, i) => i),
        importedAt: now,
      }),
    },
    {
      key: 'directory:meta',
      value: JSON.stringify({
        importedAt: now, importedBy: 'office@example.com',
        columns: COLUMNS, rowCount: PEOPLE.length,
      }),
    },
  ];
  // Pending accounts also need their index key, with the metadata the admin
  // queue reads (it lists from metadata alone, with no per-user lookup).
  for (const [email, name] of [['hopeful@example.com', 'Daniel Ortiz'],
                               ['newcomer@example.com', 'Priscilla Vance']]) {
    entries.push({ key: `pending:${email}`, value: '',
                   metadata: JSON.stringify({ name, email, createdAt: now }) });
  }
  return entries;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  assertStagingConfigured();
  const entries = await buildEntries();
  for (const e of entries) {
    const args = ['wrangler', 'kv', 'key', 'put', '--binding', 'MEMBERS_KV',
                  '--env', 'test', '--remote', e.key, e.value];
    if (e.metadata) args.push('--metadata', e.metadata);
    if (PRINT) {
      console.log('npx ' + args.map(a => /[\s"'{}]/.test(a) ? JSON.stringify(a) : a).join(' '));
    } else {
      process.stdout.write(`  ${e.key} … `);
      execFileSync('npx', args, { cwd: ROOT, stdio: ['ignore', 'ignore', 'inherit'] });
      console.log('ok');
    }
  }
  if (!PRINT) {
    console.log(`\nSeeded ${entries.length} keys into the staging namespace.\n` +
      `\n  office@example.com   → admin (put this in ADMIN_EMAILS --env test)` +
      `\n  member@example.com   → approved member` +
      `\n  hopeful@example.com  → pending (try approving it)` +
      `\n  newcomer@example.com → pending` +
      `\n\n  password for all of them: ${PASSWORD}\n`);
  }
}
