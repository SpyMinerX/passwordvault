'use strict';

// Network-only service worker — satisfies PWA installability without caching vault data.
// Passwords and session data are never stored offline.

self.addEventListener('install', (e) => {
  e.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (e) => {
  e.waitUntil(clients.claim());
});

self.addEventListener('fetch', (e) => {
  // Pass every request straight to the network — no caching
  e.respondWith(fetch(e.request));
});
