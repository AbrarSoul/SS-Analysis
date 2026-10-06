"""
Section 9 ground-truth test bundle: CASE-0304
(todbot/Blink1Control2, app/server/imapSearcher.js ImapSearcher.start,
CVE-2022-35513, CWE-327/CWE-922 use of hard-coded key material / insecure
storage of a credential).

Core vulnerable mechanism: Blink1Control2 stores the user's IMAP mailbox
password in its configuration file, "protected" with `simplecrypt`
(deprecated, keyed with `crypto.createCipher`, AES-192 in ECB mode) using a
passphrase and salt that are string LITERALS in the application source:
`simplecrypt({salt:'boopdeeboop', password:'blink1control', method:
'aes-192-ecb'})`. The key is therefore identical for every installation and
is public (the project is open source); the stored value is effectively
plaintext to anyone who can read the config file (another local user, a
backup, a cloud-synced config, a malware sample) -- they copy the two
literals and decrypt the mailbox password offline. The upstream fix removes
the hard-coded key from this file: passwords are handled by `utils.decrypt`
with per-installation key material (stored password field
`passwordHash`).

Sibling sites: the same simplecrypt literals appear wherever the password is
encrypted for storage (the UI/config code, outside this file); this file is
the decryption site in the searcher.

Verification: the top-level key setup (if present) and the password
decryption block of each full file's `ImapSearcher.prototype.start` are
extracted verbatim and run in a Node vm. `simplecrypt` is an emulation
faithful to the real module's algorithm (OpenSSL `EVP_BytesToKey` MD5 key
derivation + AES-192-ECB, message + salt), because the real
`simplecrypt` calls `crypto.createCipher`, which no longer exists in this
Node release; `utils.decrypt` (project-internal, not in the file) is a
stand-in using a random per-run key. Two measurements: (1) key material in
source -- an attacker who scrapes the salt/password/method literals out of
the FILE TEXT and builds a decryptor can decrypt a ciphertext that the app
would store (created with the app's own scheme); this works only where the
literals exist in the file; (2) `start`'s decryption block still recovers
the plaintext password from a config produced with the app's own scheme in
every variant (behaviour preserved).

Every variant is the FULL real file. `ImapSearcher.prototype.start` is used
by name by the app, so its name/signature are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0304"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


BLK = '''    var pass = '';
    try {
        pass = sc.decrypt( self.config.password );
    } catch(err) {
        log.msg('ImapSearcher: bad password');
    }
'''
assert original.count(BLK) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BLK, '''    var imapPassword = '';
    try {
        imapPassword = sc.decrypt( self.config.password );
    } catch(err) {
        log.msg('ImapSearcher: bad password');
    }
''')
assert "pass" in v1 and original.count("pass,") + original.count("pass:") + original.count("pass)") >= 0
# remaining uses of `pass` after the block must follow the rename
import re
after = v1[v1.index("var imapPassword"):]
after = re.sub(r"\bpass\b", "imapPassword", after)
v1 = v1[:v1.index("var imapPassword")] + after
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BLK, '''    var pass = decryptStoredPassword(self.config);
''')
v2 = swap(v2, "ImapSearcher.prototype.start = function() {", '''function decryptStoredPassword(config) {
    try {
        return sc.decrypt( config.password );
    } catch(err) {
        log.msg('ImapSearcher: bad password');
        return '';
    }
}

ImapSearcher.prototype.start = function() {''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, decrypt behind a helper) ---
PBLK = '''    var pass = '';
    try {
        pass = utils.decrypt( self.config.passwordHash );
    } catch(err) {
        log.msg('ImapSearcher: bad password');
    }
'''
assert patched.count(PBLK) == 1
v3 = swap(patched, PBLK, '''    var pass = readStoredPassword(self.config);
''')
v3 = swap(v3, "ImapSearcher.prototype.start = function() {", '''function readStoredPassword(config) {
    try {
        return utils.decrypt( config.passwordHash );
    } catch(err) {
        log.msg('ImapSearcher: bad password');
        return '';
    }
}

ImapSearcher.prototype.start = function() {''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''// Standalone example of the same shape: obfuscate a non-secret UI preference
// (the last-opened tab name) in local storage with a fixed key, purely to
// discourage casual hand-editing; the value is not a credential, so a
// hard-coded key has no security consequence.
var crypto = require('crypto');

var UI_KEY = crypto.createHash('sha256').update('ui-prefs-v1').digest();

function obfuscateTab(name) {
  return Buffer.from(name, 'utf8').map(function (b, i) { return b ^ UI_KEY[i % UI_KEY.length]; }).toString('base64');
}

module.exports = obfuscateTab;
''')
