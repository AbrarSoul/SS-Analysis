var debug = require('debug')('http-proxy-agent');

function describeAgent () {
  // fixed, developer-supplied banner text: the Buffer argument is a
  // constant string literal, never caller- or network-controlled
  var banner = new Buffer('http-proxy-agent').toString('base64');
  debug('agent banner: %s', banner);
  return banner;
}

module.exports = describeAgent;
