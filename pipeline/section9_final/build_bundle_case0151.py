"""
Section 9 ground-truth test bundle: CASE-0151
(electerm/electerm, src/app/lib/enc.js encrypt/decrypt/encryptAsync/decryptAsync,
CVE-2026-45787, CWE-329 / CWE-916 / CWE-326 / CWE-353 / CWE-759: static IV and
static salt, unauthenticated CBC).

Located target: `exports.decrypt = function (` (auto).

Core vulnerable mechanism: every function derives the key with
`scrypt(password, 'salt', 24)` -- a constant salt -- and encrypts with
AES-192-CBC and the constant zero IV `Buffer.alloc(16, 0)`. Consequences,
measured by running the module: the same plaintext and password always give
the SAME ciphertext (equality is visible, and identical plaintext prefixes give
identical leading blocks), there is no integrity check (a modified
ciphertext decrypts without error), and the key derivation is the same for
every user and password reuse. The upstream fix moves to AES-256-GCM with a random IV and random
salt per message, keeps a legacy path so old data still decrypts, and applies
to all four functions.

Sibling sites: encrypt, decrypt, encryptAsync and decryptAsync share the
defect (the async pair repeats the sync pair), so the safe variant fixes all
four and the vulnerable variants leave all four.

Every variant is the FULL real file. The four exports are the module's public
API, so the renamed variant renames parameters, locals and the internal
scryptAsync helper, not the exported names.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0151"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


def swap(text, old, new, count=1):
    assert text.count(old) == count and new != old, (text.count(old), old)
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = rename(original, (("scryptAsync", "deriveKeyAsync"), ("algorithmDefault", "defaultCipher"),
                       ("crypto", "nodeCrypto"), ("password", "secret"), ("algorithm", "cipherName"),
                       ("str", "plainText"), ("encrypted", "hexData"), ("decrypted", "clearText"),
                       ("iv", "initVector"), ("key", "derivedKey"), ("cipher", "encryptor"),
                       ("decipher", "decryptor"), ("args", "kdfArgs"), ("err", "kdfError"),
                       ("result", "keyBytes"), ("resolve", "done"), ("reject", "fail")))
v1 = swap(v1, "(...args)", "(...kdfArgs)")   # spread: the lookbehind skips '...'
v1 = swap(v1, "scrypt(...args,", "scrypt(...kdfArgs,")
assert "exports.encrypt = function" in v1 and "exports.decryptAsync = async function" in v1
assert "nodeCrypto.scryptSync(secret, 'salt', 24)" in v1 and "Buffer.alloc(16, 0)" in v1
assert "require('crypto')" in v1 and v1.count("await deriveKeyAsync(secret, 'salt', 24)") == 2
assert "nodeCrypto.scrypt(...kdfArgs, (kdfError, keyBytes)" in v1
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, "const algorithmDefault = 'aes-192-cbc'\n", '''const algorithmDefault = 'aes-192-cbc'
const STATIC_IV = Buffer.alloc(16, 0)
const STATIC_SALT = 'salt'
const KEY_BYTES = 24
''')
v2 = swap(v2, "  iv = Buffer.alloc(16, 0)\n", "  iv = STATIC_IV\n", count=4)
v2 = swap(v2, "crypto.scryptSync(password, 'salt', 24)", "crypto.scryptSync(password, STATIC_SALT, KEY_BYTES)", count=2)
v2 = swap(v2, "await scryptAsync(password, 'salt', 24)", "await scryptAsync(password, STATIC_SALT, KEY_BYTES)", count=2)
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# AES-256-GCM with a random IV and salt per message, packed as one base64
# blob 'v2.<base64(salt|iv|tag|ciphertext)>' (upstream uses a colon-separated
# hex string 'gcm:iv:salt:tag:ciphertext'). Old hex-only data still decrypts
# through the legacy path, as upstream does. All four functions share two
# helpers, so the sync and async pair cannot drift apart.
v3 = '''/**
 * data encrypt/decrypt
 *
 * New format: 'v2.<base64(salt(16) | iv(12) | authtag(16) | ciphertext)>' (aes-256-gcm)
 * Legacy format: pure hex (aes-192-cbc, static iv and salt), decrypt only.
 */

const algorithmDefault = 'aes-256-gcm'
const SALT_LENGTH = 16
const IV_LENGTH = 12
const TAG_LENGTH = 16
const KEY_LENGTH = 32
const PREFIX = 'v2.'

function scryptAsync (...args) {
  const crypto = require('crypto')
  return new Promise((resolve, reject) =>
    crypto.scrypt(...args, (err, result) => {
      if (err) {
        reject(err)
      }
      resolve(result)
    })
  )
}

function seal (str, key, salt, algorithm) {
  const crypto = require('crypto')
  const iv = crypto.randomBytes(IV_LENGTH)
  const cipher = crypto.createCipheriv(algorithm, key, iv)
  const body = Buffer.concat([cipher.update(str, 'utf8'), cipher.final()])
  return PREFIX + Buffer.concat([salt, iv, cipher.getAuthTag(), body]).toString('base64')
}

function unpack (encrypted) {
  const raw = Buffer.from(encrypted.slice(PREFIX.length), 'base64')
  return {
    salt: raw.subarray(0, SALT_LENGTH),
    iv: raw.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH),
    tag: raw.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH),
    body: raw.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH)
  }
}

function open (parts, key, algorithm) {
  const crypto = require('crypto')
  const decipher = crypto.createDecipheriv(algorithm, key, parts.iv)
  decipher.setAuthTag(parts.tag)
  return Buffer.concat([decipher.update(parts.body), decipher.final()]).toString('utf8')
}

function legacyDecrypt (encrypted, key) {
  const crypto = require('crypto')
  const decipher = crypto.createDecipheriv('aes-192-cbc', key, Buffer.alloc(16, 0))
  let decrypted = decipher.update(encrypted, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  return decrypted
}

exports.encrypt = function (
  str = '',
  password,
  algorithm = algorithmDefault
) {
  const crypto = require('crypto')
  const salt = crypto.randomBytes(SALT_LENGTH)
  const key = crypto.scryptSync(password, salt, KEY_LENGTH)
  return seal(str, key, salt, algorithm)
}

exports.decrypt = function (
  encrypted = '',
  password,
  algorithm = algorithmDefault
) {
  const crypto = require('crypto')
  if (!encrypted.startsWith(PREFIX)) {
    return legacyDecrypt(encrypted, crypto.scryptSync(password, 'salt', 24))
  }
  const parts = unpack(encrypted)
  const key = crypto.scryptSync(password, parts.salt, KEY_LENGTH)
  return open(parts, key, algorithm)
}

exports.encryptAsync = async function (
  str = '',
  password,
  algorithm = algorithmDefault
) {
  const crypto = require('crypto')
  const salt = crypto.randomBytes(SALT_LENGTH)
  const key = await scryptAsync(password, salt, KEY_LENGTH)
  return seal(str, key, salt, algorithm)
}

exports.decryptAsync = async function (
  encrypted = '',
  password,
  algorithm = algorithmDefault
) {
  if (!encrypted.startsWith(PREFIX)) {
    return legacyDecrypt(encrypted, await scryptAsync(password, 'salt', 24))
  }
  const parts = unpack(encrypted)
  const key = await scryptAsync(password, parts.salt, KEY_LENGTH)
  return open(parts, key, algorithm)
}
'''
assert "'salt', 24" in v3
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";
const crypto = require("crypto");

// A zero nonce is only safe when the key is NEVER reused; here every message
// gets its own random 256-bit key, so the (key, nonce) pair is unique.
const ZERO_NONCE = Buffer.alloc(12, 0);

/**
 * Same createCipheriv + fixed-IV shape as a static-IV cipher, but the key is
 * fresh and random per message and GCM authenticates the data. Returns the
 * one-time key (to be delivered out of band) and the sealed message.
 */
function sealWithOneTimeKey(plainText) {
  const key = crypto.randomBytes(32);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, ZERO_NONCE);
  const body = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  return { key: key, sealed: Buffer.concat([cipher.getAuthTag(), body]) };
}

module.exports = { sealWithOneTimeKey: sealWithOneTimeKey };
'''
assert "randomBytes(32)" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0151.")
