const CACHE_NAME = 'fm-cache-v4'
const ASSETS = [
  '/user.html',
  '/admin.html',
  '/manifest.json',
  '/logo.svg'
]
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  )
})
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.map((k) => (k !== CACHE_NAME ? caches.delete(k) : null)))).then(() => self.clients.claim())
  )
})
function isSameOrigin(url) { try { return new URL(url).origin === self.location.origin } catch { return false } }
self.addEventListener('fetch', (event) => {
  const req = event.request
  if (req.method !== 'GET') return
  const url = new URL(req.url)
  // Do not interfere with server-sent events or external tile/image requests
  if (url.pathname.startsWith('/api/admin/live')) return
  if (url.pathname.startsWith('/api/public/tiles/')) return
  if (!isSameOrigin(req.url)) return
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone(); caches.open(CACHE_NAME).then((c) => c.put(req, copy)); return res
      }).catch(() => caches.match(req).then((cached) => cached || caches.match('/user.html')))
    )
    return
  }
  if (isSameOrigin(req.url)) {
    event.respondWith(
      caches.match(req).then((cached) => {
        const fetchPromise = fetch(req).then((res) => {
          const copy = res.clone(); caches.open(CACHE_NAME).then((c) => c.put(req, copy)); return res
        }).catch(() => cached)
        return cached || fetchPromise
      })
    )
  }
})
