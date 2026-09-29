// Extract the CSV parser and the decoder straight out of the admin page HTML so
// this tests the code that actually ships, not a copy of it.
import worker from '../worker.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');


const src = readFileSync(join(ROOT, 'worker.js'), 'utf8');
const grab = (name) => {
  const start = src.indexOf(`  function ${name}(`);
  if (start < 0) throw new Error('not found: ' + name);
  let i = src.indexOf('{', start), depth = 0;
  for (let j = i; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}') { depth--; if (!depth) return src.slice(start, j + 1); }
  }
};
// The source lives inside a JS template literal, so \\r is \r in the emitted page.
const body = (grab('parseCSV') + '\n' + grab('guess') + '\n' + grab('norm'))
  .replace(/\\\\/g, '\\');
const NAME_HINTS = ['firstname','lastname','preferredname','goesby','middlename','name','suffix','nickname'];
const SHOW_HINTS = ['email','emailaddress','phone','cellphone','mobilephone','homephone','workphone',
                    'address','addressline1','addressline2','street','city','state','zip','zipcode'];
const { parseCSV, guess } = new Function('NAME_HINTS', 'SHOW_HINTS',
  body + '; return { parseCSV, guess };')(NAME_HINTS, SHOW_HINTS);

let pass = 0, fail = 0;
const out = [];
const eq = (name, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  ok ? pass++ : fail++;
  out.push(`  ${ok ? 'ok  ' : 'FAIL'} ${name}` + (ok ? '' : `\n         got:  ${JSON.stringify(got)}\n         want: ${JSON.stringify(want)}`));
};

eq('plain rows', parseCSV('a,b\n1,2'), [['a','b'],['1','2']]);
eq('CRLF line endings', parseCSV('a,b\r\n1,2\r\n'), [['a','b'],['1','2']]);
eq('UTF-8 BOM stripped', parseCSV('﻿Name,Email\nJo,j@x.com'), [['Name','Email'],['Jo','j@x.com']]);
eq('quoted comma (address)', parseCSV('Name,Addr\n"Smith, Jo","12 Main St, Apt 4"'),
   [['Name','Addr'],['Smith, Jo','12 Main St, Apt 4']]);
eq('doubled quotes', parseCSV('Name\n"He said ""hi"""'), [['Name'],['He said "hi"']]);
eq('embedded newline in quoted field', parseCSV('Name,Note\nJo,"line1\nline2"'),
   [['Name','Note'],['Jo','line1\nline2']]);
eq('empty fields preserved', parseCSV('a,b,c\n1,,3'), [['a','b','c'],['1','','3']]);
eq('trailing newline makes no phantom row', parseCSV('a,b\n1,2\n'), [['a','b'],['1','2']]);
eq('ragged short row kept as-is', parseCSV('a,b,c\n1,2'), [['a','b','c'],['1','2']]);
eq('quoted field containing CRLF', parseCSV('a\n"x\r\ny"'), [['a'],['x\ny']]);
eq('single column', parseCSV('Email\na@b.com\nc@d.com'), [['Email'],['a@b.com'],['c@d.com']]);

// Column auto-guessing: conservative whitelist only.
eq('First Name pre-ticked as name',  guess('First Name'),  { show: true,  name: true,  search: true  });
eq('E-mail pre-ticked as show only', guess('E-mail'),      { show: true,  name: false, search: true  });
eq('Cell Phone pre-ticked',          guess('Cell Phone'),  { show: true,  name: false, search: true  });
eq('Zip Code pre-ticked',            guess('Zip Code'),    { show: true,  name: false, search: true  });

// The whole point: sensitive columns must never be pre-ticked.
for (const col of ['Total Contributions 2025','Birth Date','Date of Birth','Marital Status',
                   'Background Check','Pledge Amount','Deceased','Individual ID','Offering YTD','SSN']) {
  eq(`"${col}" NOT pre-ticked`, guess(col), { show: false, name: false, search: false });
}

// A realistic Servant Keeper-shaped export.
const sk = '﻿"Family ID","Individual ID","First Name","Last Name","E-mail","Cell Phone",' +
           '"Address Line 1","City","State","Zip","Birth Date","Total Contributions"\r\n' +
           '"1","1","José","Núñez","jose@example.com","(256) 555-0100","1 Oak St, Apt 2",' +
           '"Huntsville","AL","35811","1980-04-01","1250.00"\r\n' +
           '"2","2","Mary Ann","O""Brien","mary@example.com","256-555-0101","2 Elm Ave",' +
           '"Huntsville","AL","35811","1975-11-12","800.00"\r\n';
const rows = parseCSV(sk);
eq('SK export: row count', rows.length, 3);
eq('SK export: header intact', rows[0][0], 'Family ID');
eq('SK export: accented name', rows[1][2], 'José');
eq('SK export: comma inside quoted address', rows[1][6], '1 Oak St, Apt 2');
eq('SK export: escaped quote in surname', rows[2][3], 'O"Brien');

const header = rows[0];
const ticked = header.filter(h => guess(h).show);
eq('SK export: sensitive columns excluded by default', ticked,
   ['First Name','Last Name','E-mail','Cell Phone','Address Line 1','City','State','Zip']);

// CP1252 fallback. NOTE: Node maps 0x92 to U+0092 (ISO-8859-1 semantics); a
// browser, per the WHATWG Encoding Standard, maps it to U+2019. This code only
// ever runs in a browser, so assert what Node can actually verify: that strict
// UTF-8 rejects the bytes (triggering the fallback) and the fallback decodes
// every byte without loss or replacement characters.
const cp1252 = new Uint8Array([0x4F, 0x92, 0x42, 0x72, 0x69, 0x65, 0x6E]); // O’Brien in CP1252
let threw = false;
try { new TextDecoder('utf-8', { fatal: true }).decode(cp1252); } catch { threw = true; }
eq('strict UTF-8 rejects CP1252 bytes, triggering the fallback', threw, true);
const fellBack = new TextDecoder('windows-1252').decode(cp1252);
eq('fallback decodes every byte', fellBack.length, 7);
eq('fallback produces no replacement characters', fellBack.includes('\uFFFD'), false);

// Valid UTF-8 must NOT take the fallback path.
eq('valid UTF-8 decodes strictly',
   new TextDecoder('utf-8', { fatal: true }).decode(new TextEncoder().encode('José')), 'José');

console.log(out.join('\n'));
console.log(`\n  ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
