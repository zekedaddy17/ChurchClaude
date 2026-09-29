#!/usr/bin/env node
/**
 * Dependency-free test suite. Run with:  node tests/run.mjs
 *
 * Covers the auth/approval model, the /members route gating, the CSV parser and
 * column auto-guessing, and a syntax check of every <script> the Worker inlines
 * into a page (which `node --check worker.js` cannot see, because those scripts
 * live inside template literals).
 */
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const suites = ['worker.test.mjs', 'csv.test.mjs', 'pages.test.mjs'];
let failed = 0;

for (const s of suites) {
  process.stdout.write(`\n\x1b[1m▸ ${s}\x1b[0m\n`);
  try {
    process.stdout.write(execFileSync('node', [join(here, s)], { encoding: 'utf8' }));
  } catch (e) {
    failed++;
    process.stdout.write((e.stdout || '') + (e.stderr || ''));
  }
}

console.log(failed ? `\n\x1b[31m${failed} suite(s) failed\x1b[0m\n` : '\n\x1b[32mAll suites passed\x1b[0m\n');
process.exit(failed ? 1 : 0);
