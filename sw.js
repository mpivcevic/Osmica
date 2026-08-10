const CACHE = 'zm-v5';
const STATIC = ['./manifest.json', './icon-192.png', './icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(STATIC)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
      .then(() => self.clients.matchAll({ includeUncontrolled: true }))
      .then(clients => clients.forEach(c => c.postMessage({ type: 'SW_UPDATED' })))
  );
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);

  // Never touch cross-origin requests. Supabase reads are GETs whose paths
  // don't end in .html, so without this they fell into the cache-first branch
  // below and the app served stale rows forever (a waiter's joined_at would
  // stay null after they joined, sending them back through PIN setup). The
  // Supabase API and the CDN script are network-only; the browser's own HTTP
  // cache still applies to them and respects their cache headers.
  if (url.origin !== self.location.origin) return;

  // HTML: always fetch from network, never cache — guarantees fresh version on every open
  if (url.pathname.endsWith('.html') || url.pathname.endsWith('/')) {
    e.respondWith(fetch(e.request));
    return;
  }

  // Static assets: cache-first
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        // Clone synchronously: caches.open() is async, so by the time its
        // .then() runs the body of `res` is already being consumed by the page
        // and clone() would throw.
        const copy = res.clone();
        if (res.ok) caches.open(CACHE).then(c => c.put(e.request, copy));
        return res;
      });
    })
  );
});
