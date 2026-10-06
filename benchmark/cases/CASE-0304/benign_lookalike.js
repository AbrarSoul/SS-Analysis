// Standalone example of the same shape: obfuscate a non-secret UI preference
// (the last-opened tab name) in local storage with a fixed key, purely to
// discourage casual hand-editing; the value is not a credential, so a
// hard-coded key has no security consequence.
var crypto = require('crypto');

var UI_KEY = crypto.createHash('sha256').update('ui-prefs-v1').digest();

function obfuscateTab(name) {
  return Buffer.from(name, 'utf8').map(function (b, i) { return b ^ UI_KEY[i % UI_KEY.length]; }).toString('base64');
}

module.exports = obfuscateTab;
