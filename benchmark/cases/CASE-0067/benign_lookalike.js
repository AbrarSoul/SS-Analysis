function pingHealthEndpointOnce(client, url) {
  // Fires exactly once, at server startup -- never attached to a
  // repeating stream of events, so there is no way this callback could
  // ever be invoked more than a handful of times in a process lifetime.
  client.get(url, function (error) {
    if (error) console.log('Health check failed: ' + error.message);
  });
}

module.exports = { pingHealthEndpointOnce };
