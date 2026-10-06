/**
 * Parse a CSS-style hex colour such as "#abc" or "#aabbcc" into [r, g, b].
 * The pattern has no nested or overlapping quantifiers and only accepts 3 or
 * 6 hex digits, so matching is linear and bounded regardless of input.
 */
module.exports = function parseHexColor(str) {
  var match = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(String(str));
  if (!match) {
    return;
  }
  var hex = match[1];
  if (hex.length === 3) {
    hex = hex.replace(/./g, '$&$&');
  }
  return [0, 2, 4].map(function(i) {
    return parseInt(hex.slice(i, i + 2), 16);
  });
};
