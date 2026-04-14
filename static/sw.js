/**
 * Service Worker — Graceful Degradation & Offline Queue
 *
 * Strategy:
 *   - Cache-first for static assets (HTML, CSS, fonts, example images)
 *   - Network-first for API calls
 *   - Queue failed POST/PATCH/DELETE in IndexedDB → auto-sync on reconnect
 */

const CACHE_NAME = 'sadtalker-v1';
const STATIC_ASSETS = [
  '/',
  '/login',
  '/static/index.html',
  '/static/login.html',
];

// ── Install: pre-cache shell ──
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(c => c.addAll(STATIC_ASSETS))
  );
  self.skipWaiting();
});

// ── Activate: clean old caches ──
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// ── Fetch: network-first for API, cache-first for static ──
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // API calls: network-first
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(
      fetch(e.request).catch(() => {
        // Offline: return cached or error JSON
        if (e.request.method === 'GET') {
          return caches.match(e.request).then(r => r || new Response(
            JSON.stringify({ detail: 'ออฟไลน์ — ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้' }),
            { status: 503, headers: { 'Content-Type': 'application/json' } }
          ));
        }
        // Queue mutation for sync
        return queueAction(e.request.clone()).then(() =>
          new Response(JSON.stringify({ queued: true, detail: 'บันทึกคำสั่งไว้แล้ว จะดำเนินการเมื่อออนไลน์' }),
            { status: 202, headers: { 'Content-Type': 'application/json' } })
        );
      })
    );
    return;
  }

  // Static: cache-first with network fallback
  e.respondWith(
    caches.match(e.request).then(cached => {
      const fetched = fetch(e.request).then(resp => {
        // Update cache with fresh version
        if (resp.ok) {
          const clone = resp.clone();
          caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        }
        return resp;
      }).catch(() => cached);
      return cached || fetched;
    })
  );
});

// ── IndexedDB queue for offline mutations ──
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('sadtalker-queue', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('queue', { autoIncrement: true });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function queueAction(request) {
  const db = await openDB();
  const body = await request.text();
  const tx = db.transaction('queue', 'readwrite');
  tx.objectStore('queue').add({
    url: request.url,
    method: request.method,
    headers: Object.fromEntries(request.headers),
    body,
    timestamp: Date.now(),
  });
  return new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = reject;
  });
}

async function syncQueue() {
  const db = await openDB();
  const tx = db.transaction('queue', 'readonly');
  const store = tx.objectStore('queue');
  const all = await new Promise(resolve => {
    const req = store.getAll();
    req.onsuccess = () => resolve(req.result);
  });
  const keys = await new Promise(resolve => {
    const req = store.getAllKeys();
    req.onsuccess = () => resolve(req.result);
  });

  for (let i = 0; i < all.length; i++) {
    const item = all[i];
    try {
      await fetch(item.url, {
        method: item.method,
        headers: item.headers,
        body: item.method !== 'GET' ? item.body : undefined,
      });
      // Success: remove from queue
      const delTx = db.transaction('queue', 'readwrite');
      delTx.objectStore('queue').delete(keys[i]);
    } catch (e) {
      break; // Still offline, stop trying
    }
  }

  // Notify all clients that sync completed
  const clients = await self.clients.matchAll();
  clients.forEach(c => c.postMessage({ type: 'sync-complete' }));
}

// ── Background Sync (auto-retry when online) ──
self.addEventListener('sync', (e) => {
  if (e.tag === 'sync-queue') {
    e.waitUntil(syncQueue());
  }
});

// ── Fallback: periodic sync check via message ──
self.addEventListener('message', (e) => {
  if (e.data === 'sync-now') {
    syncQueue();
  }
});
