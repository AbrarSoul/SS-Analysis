"""
Section 9 ground-truth test bundle: CASE-0271
(pyca/cryptography, src/cryptography/hazmat/backends/openssl/rsa.py
_enc_dec_rsa_pkey_ctx, CVE-2020-25659, CWE-385 covert timing channel
(Bleichenbacher-style RSA padding oracle)).

Core vulnerable mechanism: after the raw RSA encrypt/decrypt operation
(`crypt(...)`), the vulnerable code takes a COMPLETELY DIFFERENT, ASYMMETRIC
path depending on success vs failure: on success it does one cheap buffer
read; on failure (`res <= 0`, e.g. invalid PKCS#1 v1.5 padding during
decryption) it calls `_handle_rsa_enc_dec_error`, which calls
`backend._consume_errors_with_text()` -- a function that drains OpenSSL's
entire thread-local error queue and formats each entry into human-readable
text, work the success path never does. For an application exposing RSA
PKCS#1 v1.5 decryption to attacker-influenced ciphertexts (a "decryption
oracle," e.g. an old-style RSA key exchange or any endpoint that decrypts
attacker-supplied data and reveals ANY observable side effect of success vs
failure -- even indirectly, e.g. via response timing), the extra
error-queue-draining work on the failure path is measurably slower than the
success path. An attacker who can time many decryption attempts can use that
asymmetry as a padding oracle (a Bleichenbacher/"Million Message Attack"
variant) to recover the plaintext of an intercepted RSA ciphertext, or forge
signatures, without ever learning the private key. The upstream fix makes
BOTH paths do the identical, cheap, constant-time work --
`backend._lib.ERR_clear_error()` (an O(1) call that just resets the error
queue, versus draining and formatting it) -- regardless of whether `res`
indicates success or failure, and raises one generic message with no
key-type-dependent branching.

Sibling sites: `_handle_rsa_enc_dec_error` is a standalone helper called
from exactly one place (`_enc_dec_rsa_pkey_ctx`); there is one call site to
fix, though the fix also removes the helper function entirely (folding its
one remaining behavior -- raising -- inline).

Verification: each full file is copied over the real, installed
`cryptography` package's own `.../backends/openssl/rsa.py` (`cryptography`
pip-installed into a venv; `cryptography.utils.verify_interface` is
patched to skip its ABC-completeness check, since this ~2020-era file
predates a couple of interface methods added to the ABCs by later
`cryptography` releases -- registration itself, which is what actually
matters for `isinstance` checks used elsewhere, is left untouched) so
`_enc_dec_rsa_pkey_ctx` runs as real, unmodified code against a REAL RSA-2048
keypair and REAL OpenSSL FFI calls. `backend._consume_errors_with_text` is
wrapped with a call-counter (not timed -- a call COUNT is a deterministic,
non-flaky stand-in for the same asymmetry a real attacker would measure via
wall-clock timing). A real `PKCS1v15`-padded ciphertext is decrypted (the
success case) and 256 random bytes are decrypted (a value overwhelmingly
unlikely to carry valid PKCS#1 v1.5 padding, forcing the OpenSSL-level
failure path) -- the call counter is compared between the two.

Every variant is the FULL real file. `_enc_dec_rsa_pkey_ctx` is called
internally by `_enc_dec_rsa` (this file's own public entry point used by
`RSAPublicKey.encrypt`/`RSAPrivateKey.decrypt`), so its name and signature
are kept; the renamed variant renames its own locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0271"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


TAIL = '''    outlen = backend._ffi.new("size_t *", buf_size)
    buf = backend._ffi.new("unsigned char[]", buf_size)
    res = crypt(pkey_ctx, buf, outlen, data, len(data))
    if res <= 0:
        _handle_rsa_enc_dec_error(backend, key)

    return backend._ffi.buffer(buf)[: outlen[0]]


def _handle_rsa_enc_dec_error(backend, key):
    errors = backend._consume_errors_with_text()
    if isinstance(key, _RSAPublicKey):
        raise ValueError(
            "Data too long for key size. Encrypt less data or use a "
            "larger key size.",
            errors,
        )
    else:
        raise ValueError("Decryption failed.", errors)'''
assert original.count(TAIL) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, TAIL, '''    result_len = backend._ffi.new("size_t *", buf_size)
    result_buf = backend._ffi.new("unsigned char[]", buf_size)
    status = crypt(pkey_ctx, result_buf, result_len, data, len(data))
    if status <= 0:
        _handle_rsa_enc_dec_error(backend, key)

    return backend._ffi.buffer(result_buf)[: result_len[0]]


def _handle_rsa_enc_dec_error(backend, key):
    error_text = backend._consume_errors_with_text()
    if isinstance(key, _RSAPublicKey):
        raise ValueError(
            "Data too long for key size. Encrypt less data or use a "
            "larger key size.",
            error_text,
        )
    else:
        raise ValueError("Decryption failed.", error_text)''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, TAIL, '''    outlen = backend._ffi.new("size_t *", buf_size)
    buf = backend._ffi.new("unsigned char[]", buf_size)
    res = crypt(pkey_ctx, buf, outlen, data, len(data))
    return _finish_rsa_enc_dec(backend, key, res, buf, outlen)


def _finish_rsa_enc_dec(backend, key, res, buf, outlen):
    if res <= 0:
        _handle_rsa_enc_dec_error(backend, key)
    return backend._ffi.buffer(buf)[: outlen[0]]


def _handle_rsa_enc_dec_error(backend, key):
    errors = backend._consume_errors_with_text()
    if isinstance(key, _RSAPublicKey):
        raise ValueError(
            "Data too long for key size. Encrypt less data or use a "
            "larger key size.",
            errors,
        )
    else:
        raise ValueError("Decryption failed.", errors)''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (identical, cheap ERR_clear_error() work on
# both the success and failure path, no expensive error-queue draining
# gated behind the failure branch) but the "did it fail" check is deferred
# into a small helper called AFTER the buffer read/clear, instead of
# upstream's inline `if res <= 0: raise`.
v3 = swap(original, TAIL, '''    outlen = backend._ffi.new("size_t *", buf_size)
    buf = backend._ffi.new("unsigned char[]", buf_size)
    # Everything from this line onwards is written with the goal of being as
    # constant-time as is practical given the constraints of Python and our
    # API. See Bleichenbacher's '98 attack on RSA, and its many many variants.
    # As such, you should not attempt to change this (particularly to "clean it
    # up") without understanding why it was written this way (see
    # Chesterton's Fence), and without measuring to verify you have not
    # introduced observable time differences.
    res = crypt(pkey_ctx, buf, outlen, data, len(data))
    resbuf = backend._ffi.buffer(buf)[: outlen[0]]
    backend._lib.ERR_clear_error()
    _raise_if_rsa_enc_dec_failed(res)
    return resbuf


def _raise_if_rsa_enc_dec_failed(res):
    if res <= 0:
        raise ValueError("Encryption/decryption failed.")''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""
Standalone example of the same shape: after a lookup, run a slightly
heavier "not found, build a helpful suggestion list" step only when the
lookup misses. The list only affects what appears in a LOCAL log message
never sent back to any caller or exposed over the network, so the extra
work only running on the miss path leaks no information to any external
observer.
"""


def _build_suggestions(catalog, query):
    return [name for name in catalog if name.lower().startswith(query[:1].lower())]


def lookup_and_log(catalog, query, logger):
    if query in catalog:
        return catalog[query]
    suggestions = _build_suggestions(catalog, query)
    logger.info("no match for %r, maybe: %r", query, suggestions)
    return None
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
