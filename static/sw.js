const CACHE_NAME = 'messenger-v1';
const urlsToCache = [
  '/',
  '/chats',
  '/static/manifest.json'
];

// Установка Service Worker
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        return cache.addAll(urlsToCache);
      })
  );
});

// Активация
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Перехват запросов
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        if (response) {
          return response;
        }
        return fetch(event.request);
      })
  );
});

// ПУШ УВЕДОМЛЕНИЯ (бесплатные)
self.addEventListener('push', event => {
  const data = event.data.json();
  const options = {
    body: data.body,
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-72.png',
    vibrate: [200, 100, 200],
    data: {
      url: data.url || '/chats'
    }
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title, options)
  );
});

// Клик по уведомлению
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.openWindow(event.notification.data.url)
  );
});