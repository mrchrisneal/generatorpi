
self.addEventListener('push', function(event){
  var data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) {}
  var title = data.title || 'Generator';
  var opts = { body: data.body || '', tag: data.tag || 'generatorpi', renotify: true };
  event.waitUntil(self.registration.showNotification(title, opts));
});
self.addEventListener('notificationclick', function(event){
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(list){
      for (var i = 0; i < list.length; i++){ if ('focus' in list[i]) return list[i].focus(); }
      if (clients.openWindow) return clients.openWindow('/');
    })
  );
});
