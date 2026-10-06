// CyberShield UI — service worker minimo (instalabilidad PWA)
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()));
self.addEventListener('fetch', () => {});
