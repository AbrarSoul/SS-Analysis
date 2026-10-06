r"""
Section 9 ground-truth test bundle: CASE-0311
(trevp/tlslite, tlslite/tlsrecordlayer.py _decryptRecord, CVE-2015-3220,
CWE-119 improper restriction of operations within the bounds of a buffer).

Core vulnerable mechanism: for a block-cipher record, `_decryptRecord`
decrypts the ciphertext and, for TLS 1.1+, strips the explicit IV
(`b = b[block_size:]`). A peer that sends a record containing exactly one
block (or, for older versions, an empty record) leaves `b` empty, and the next
statement `paddingLength = b[-1]` reads outside the buffer: an IndexError that
escapes the TLS alert machinery and crashes the connection handler
(remote denial of service) instead of a decryption_failed alert. The upstream
fix inserts a `len(b) == 0` check after IV removal that sends
decryption_failed.

Sibling sites: the later `b[-totalPaddingLength:-1]` and `b[:-endLength]`
slices are guarded by `(paddingLength+1) > len(b)` and `endLength > len(b)`.

Verification: the `_decryptRecord` method (plus a helper method that a
variant extracts next to it) is sliced out of each full file and exec'd into a
stub class with a block-cipher read state (16-byte block, identity decrypt)
and a real HMAC-SHA1 MAC context; `_sendError` raises a stub alert exception.
Three records are fed through: a valid TLS 1.1 record (IV + payload + HMAC +
padding) which must return the payload in every file, a one-block record
(empty after IV removal), and an empty TLS 1.0 record. Vulnerable variants
raise IndexError for the empty cases; patched/safe raise the
decryption_failed alert.

Every variant is the FULL real file; `_decryptRecord` keeps its name because
the record layer calls it by name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0311"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


START = "    def _decryptRecord(self, recordType, b):\n"
END = "    def _handshakeStart(self, client):\n"
assert original.count(START) == 1 and original.count(END) == 1
func = original[original.index(START):original.index(END)]

# --- Variant 1: renamed vulnerable variant (parameter and locals renamed inside _decryptRecord) ---
f1 = func
for old, new in [("b", "record"), ("blockLength", "blockSize"), ("paddingGood", "padOk"),
                 ("paddingLength", "padValue"), ("totalPaddingLength", "padTotal"),
                 ("macGood", "macOk"), ("checkBytes", "claimedMac")]:
    f1 = re.sub(r"\b%s\b" % old, new, f1)
assert " b " not in f1 and "b[" not in f1 and "(b)" not in f1
v1 = original.replace(func, f1)
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (IV removal moved into a helper method) ---
IV = "                    b = b[self._readState.encContext.block_size : ]\n"
f2 = swap(func, IV, "                    b = self._stripExplicitIV(b)\n")
f2 = f2.rstrip("\n") + "\n\n    def _stripExplicitIV(self, data):\n        return data[self._readState.encContext.block_size:]\n\n"
v2 = original.replace(func, f2)
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the emptiness test becomes an IndexError guard on the read) ---
CHECK = '''                if len(b) == 0:
                    for result in self._sendError(\\
                            AlertDescription.decryption_failed,
                            "No data left after decryption and IV removal"):
                        yield result

'''
assert patched.count(CHECK) == 1
v3 = patched.replace(CHECK, "")
v3 = swap(v3, "                paddingLength = b[-1]\n", '''                try:
                    paddingLength = b[-1]
                except IndexError:
                    for result in self._sendError(\\
                            AlertDescription.decryption_failed,
                            "No data left after decryption and IV removal"):
                        yield result
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""Framing helper: strips the leading nonce and trailing pad from a buffer this module built itself."""


def frame(payload: bytes, nonce: bytes = b"\\x00" * 16) -> bytes:
    """Build nonce + payload + one pad-length byte."""
    return nonce + payload + bytes([1])


def unframe(framed: bytes, nonce_len: int = 16) -> bytes:
    """Undo frame().

    `framed` is always the output of frame() in this same process, so it is
    at least nonce_len + 1 bytes long by construction; the last-byte read
    below can never run off the end of the buffer.
    """
    body = framed[nonce_len:]
    pad = body[-1]
    return body[:len(body) - pad]
''')
