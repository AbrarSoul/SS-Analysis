// Standalone example of the same shape: a scheme denylist for a link checker
// that only decides which links get a "leaves the site" icon; nothing is
// rendered as active content because of the result.
var EXTERNAL_SCHEMES = [ 'http', 'https', 'ftp' ];

function isExternalLink(url) {
  var str = url.trim().toLowerCase();

  return str.indexOf(':') >= 0 && EXTERNAL_SCHEMES.indexOf(str.split(':')[0]) >= 0;
}

module.exports = isExternalLink;
