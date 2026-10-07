import worker from '../worker.js';

// Trimmed-down copies of what youtube.com/channel/<id>/live returns
const page = ({ id = '2t50TMXfE4c', title = 'October 11, 2026 Chase Park Sunday Morning Services',
                liveNow = false, upcoming = false, start = null, canonical = true } = {}) => `<html><head>
${canonical ? `<link rel="canonical" href="https://www.youtube.com/watch?v=${id}">` : ''}
</head><body><script>var ytInitialPlayerResponse = {"videoDetails":{"videoId":"${id}","title":${JSON.stringify(title)},"isLiveContent":true${upcoming ? ',"isUpcoming":true' : ''}},
${start ? `"liveStreamability":{"offlineSlateRenderer":{"scheduledStartTime":"${start}"}},` : ''}
"microformat":{"playerMicroformatRenderer":{"liveBroadcastDetails":{"isLiveNow":${liveNow},"startTimestamp":"2026-10-11T14:00:00+00:00"}}}};</script></body></html>`;

let pass = 0, fail = 0;
const check = (n, c, d = '') => c ? (pass++, console.log(`  ok   ${n}`))
                                  : (fail++, console.log(`  FAIL ${n}${d ? ' — ' + d : ''}`));

let fetchCalls = 0, livePage;
globalThis.fetch = async () => { fetchCalls++; return livePage(); };

const env = { MEMBERS_KV: null, ASSETS: { fetch: async () => new Response('asset') } };
const get = async () => (await worker.fetch(new Request('https://t.test/api/live'), env)).json();

// The Worker caches for a minute per isolate; step the clock past it between cases.
let now = Date.now();
Date.now = () => now;
const next = () => { now += 61 * 1000; };
const sec = () => Math.floor(now / 1000);

livePage = () => new Response(page({ liveNow: true }));
let r = await get();
check('live when isLiveNow is true', r.status === 'live' && r.videoId === '2t50TMXfE4c');
check('live title read from the player data', r.title === 'October 11, 2026 Chase Park Sunday Morning Services');

const calls = fetchCalls;
await get();
check('served from cache within a minute', fetchCalls === calls);

next();
livePage = () => new Response(page({ upcoming: true, start: sec() - 60 * 60 * 24 * 600 }));
r = await get();
check('stale scheduled stream from long ago is offline', r.status === 'offline' && !r.videoId);

next();
livePage = () => new Response(page({ upcoming: true, start: sec() + 30 * 60 }));
r = await get();
check('stream starting within the hour is upcoming', r.status === 'upcoming' && typeof r.startsAt === 'string');

next();
livePage = () => new Response(page({ upcoming: true, start: sec() + 5 * 24 * 60 * 60 }));
r = await get();
check('stream scheduled days out is offline', r.status === 'offline');

next();
livePage = () => new Response(page({ liveNow: false }));
r = await get();
check('finished stream is offline', r.status === 'offline');

next();
livePage = () => new Response(page({ canonical: false }));
r = await get();
check('no video at all is offline', r.status === 'offline');

next();
livePage = () => new Response(page({ liveNow: true, title: 'Say "Amen" \\ Psalms' }));
r = await get();
check('escaped quotes in title decoded', r.title === 'Say "Amen" \\ Psalms');

next();
livePage = () => new Response('nope', { status: 500 });
r = await get();
check('YouTube error keeps the last answer', r.status === 'live');

console.log(`\n  ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
