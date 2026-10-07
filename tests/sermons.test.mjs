import worker from '../worker.js';

class KV {
  constructor() { this.store = new Map(); }
  async get(k) { return this.store.has(k) ? this.store.get(k) : null; }
  async put(k, v) { this.store.set(k, v); }
  async delete(k) { this.store.delete(k); }
}

const entry = (id, title, published, description = title) => `
 <entry>
  <id>yt:video:${id}</id>
  <yt:videoId>${id}</yt:videoId>
  <title>${title}</title>
  <published>${published}</published>
  <media:group>
   <media:title>${title}</media:title>
   <media:description>${description}</media:description>
  </media:group>
 </entry>`;

const FEED = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns:yt="http://www.youtube.com/xml/schemas/2015" xmlns:media="http://search.yahoo.com/mrss/">
 <title>Chase Park Church of Christ</title>
 <published>2009-05-18T17:01:58+00:00</published>
${entry('Zl0noB6FBJQ', 'October 4, 2026 Chase Park Sunday Evening Services', '2026-10-05T11:07:42+00:00')}
${entry('hfomsroE-I8', 'October 4, 2026 Chase Park Sunday Morning Services', '2026-10-05T04:22:59+00:00')}
${entry('8tMU1qSVTfk', 'Faith &amp; Works', '2026-10-02T23:12:27+00:00', 'September 27th, 2026 Morning Lesson')}
${entry('aaaaaaaaaaa', 'September 30, 2026 Wednesday Night Services', '2026-10-01T01:00:00+00:00')}
${entry('bbbbbbbbbbb', 'September 29, 2026 Special Emphasis: Day 3', '2026-09-30T01:00:00+00:00')}
${entry('ccccccccccc', 'A Trip Down Memory Lane', '2026-09-21T02:00:00+00:00')}
</feed>`;

let pass = 0, fail = 0;
const check = (n, c, d = '') => c ? (pass++, console.log(`  ok   ${n}`))
                                  : (fail++, console.log(`  FAIL ${n}${d ? ' — ' + d : ''}`));

let fetchCalls = 0, feedResponse;
globalThis.fetch = async () => { fetchCalls++; return feedResponse(); };

const kv  = new KV();
const env = { MEMBERS_KV: kv, ASSETS: { fetch: async () => new Response('asset') } };
const get = () => worker.fetch(new Request('https://t.test/api/sermons'), env);

// ── Fresh fetch ────────────────────────────────────────────────────────────
feedResponse = () => new Response(FEED, { status: 200 });
let res  = await get();
let body = await res.json();
check('200 on a good feed', res.status === 200);
check('publicly cacheable', /public/.test(res.headers.get('Cache-Control')));
check('all entries, channel title skipped', body.videos.length === 6 &&
      !body.videos.some(v => v.title === 'Chase Park Church of Christ'));
check('newest first, ids intact', body.videos[0].videoId === 'Zl0noB6FBJQ' && body.videos[1].videoId === 'hfomsroE-I8');
check('entities decoded', body.videos[2].title === 'Faith & Works');
check('categories from titles', body.videos.map(v => v.category).join() ===
      'Sunday Evening,Sunday Morning,Lessons,Wednesday,Special,Lessons');
check('description dropped when it only repeats the title', body.videos[0].description === '');
check('description kept when it adds something', body.videos[2].description === 'September 27th, 2026 Morning Lesson');
check('leading date stripped from title', body.videos[0].title === 'Chase Park Sunday Evening Services' &&
      body.videos[4].title === 'Special Emphasis: Day 3');
check('date from title, not upload time', body.videos[0].date === '2026-10-04');
check('date from description when title has none', body.videos[2].date === '2026-09-27');
check('date falls back to upload time', body.videos[5].date === '2026-09-21');
check('no date field leaks upload timestamp format', body.videos.every(v => /^\d{4}-\d{2}-\d{2}$/.test(v.date)));

// ── Within TTL: no refetch ─────────────────────────────────────────────────
await get();
check('served from cache within TTL', fetchCalls === 1);

// ── Stale cache + feed failure: serve stale ────────────────────────────────
const stale = JSON.parse(kv.store.get('sermons:feed'));
stale.fetchedAt -= 31 * 60 * 1000;
kv.store.set('sermons:feed', JSON.stringify(stale));
feedResponse = () => new Response('Not Found', { status: 404 });
res  = await get();
body = await res.json();
check('refetches after TTL', fetchCalls === 2);
check('falls back to stale copy on 404', res.status === 200 && body.videos.length === 6);

feedResponse = () => { throw new Error('network down'); };
res = await get();
check('falls back to stale copy on network error', res.status === 200);

// ── No cache + feed failure: 502 ───────────────────────────────────────────
kv.store.clear();
feedResponse = () => new Response('Not Found', { status: 404 });
res = await get();
check('502 when feed fails and nothing cached', res.status === 502);

feedResponse = () => new Response('<feed><title>x</title></feed>', { status: 200 });
res = await get();
check('empty feed treated as failure', res.status === 502 && !kv.store.has('sermons:feed'));

console.log(`\n  ${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
