// Same ignoreProperties.indexOf(segment) guard shape, but every path handled
// here is a fixed, developer-written array literal of string constants; no
// externally supplied (or non-string) segment can ever reach it.
var ignoreProperties = ['__proto__', 'constructor', 'prototype'];

var SETTINGS_PATHS = {
  port: ['server', 'port'],
  host: ['server', 'host']
};

exports.readSetting = function(name, config) {
  var parts = SETTINGS_PATHS[name];
  if (!parts) return undefined;
  var cur = config;
  for (var i = 0; i < parts.length; ++i) {
    if (ignoreProperties.indexOf(parts[i]) !== -1) return undefined;
    if (cur == null) return undefined;
    cur = cur[parts[i]];
  }
  return cur;
};
