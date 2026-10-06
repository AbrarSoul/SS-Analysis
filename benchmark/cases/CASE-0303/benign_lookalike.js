// Standalone example of the same shape: copy the keys of a trusted,
// application-owned defaults table (a literal in this file, never parsed
// from external input) into a fresh object.
var DEFAULTS = { color: 'blue', size: 'm' };

function withDefaults(overrides) {
  var out = {};
  Object.keys(DEFAULTS).forEach(function (k) { out[k] = DEFAULTS[k]; });
  Object.keys(overrides || {}).forEach(function (k) { out[k] = overrides[k]; });
  return out;
}

module.exports = withDefaults;
