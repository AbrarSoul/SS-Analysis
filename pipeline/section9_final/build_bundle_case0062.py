"""
Section 9 ground-truth test bundle: CASE-0062
(Morgan-Phoenix/EnroCrypt, CVE-2021-39182, CWE-326/327/328/916 use of a
broken/risky cryptographic hash algorithm).

Core vulnerable mechanism: the `Hashing` class exposes an `MD5()` method
that hashes caller-supplied data with `hashlib.md5()`. MD5 is
cryptographically broken -- fast collisions are computable, and it has no
place in a class whose whole purpose is offering hash primitives for
security-relevant use (the class's own docstring is literally "Hashing
Funcitions In Here"). The real fix simply DELETES the `MD5()` method
entirely from the library's public API, rather than trying to make MD5
itself safe (it can't be) -- so there is no direct "before/after" code
pair for this one; the safe reference for Section 9 purposes is
constructed as a comparably-shaped method using a real cryptographic hash
instead, consistent with the OTHER methods already in this same class
(SHA256/SHA512/SHA244).
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0062"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    def MD5(self,data:str):
        sha = hashlib.md5(bytes(data.encode()))
        hash = str(sha.digest())
        return self.__Salt(hash,salt=self.salt)'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename MD5 -> LegacyHash, data -> payload. Same exact hashlib.md5() use.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def LegacyHash(self,payload:str):
        sha = hashlib.md5(bytes(payload.encode()))
        hash = str(sha.digest())
        return self.__Salt(hash,salt=self.salt)''',
)
assert "def LegacyHash(self,payload:str):" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the raw bytes before hashing.
# Same exact hashlib.md5() use, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def MD5(self,data:str):
        raw_bytes = bytes(data.encode())
        sha = hashlib.md5(raw_bytes)
        digest_str = str(sha.digest())
        return self.__Salt(digest_str,salt=self.salt)''',
)
assert structural_source != original
assert "raw_bytes = bytes(data.encode())" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same overall purpose (a keyed/salted hash method on this class) but
# built around hashlib.blake2b() with an explicit digest_size, instead of
# the class's own pre-existing SHA-family methods -- genuinely a strong,
# modern cryptographic hash, materially different choice/shape from any
# method already in the file.
SAFE_SOURCE = '''    def StrongHash(self,data:str):
        sha = hashlib.blake2b(bytes(data.encode()), digest_size=32)
        hash = str(sha.digest())
        return self.__Salt(hash,salt=self.salt)'''
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_SOURCE)
assert safe_source != original
assert "hashlib.blake2b" in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Same visible shape (call hashlib.md5() on some bytes and return a
# digest-derived string) but this sibling only uses the digest as a
# NON-SECURITY cache key -- deduplicating identical file uploads in a
# local disk cache, where MD5's cryptographic weakness (collision
# forgeability) is irrelevant because nothing security-sensitive depends
# on collision resistance: a deliberate collision would at worst merge
# two cache entries, not bypass any check. Genuinely safe despite calling
# the same API as the vulnerable Hashing.MD5().
BENIGN_SOURCE = '''import hashlib


class UploadCache:
    """Deduplicates identical file uploads in a local disk cache using a
    content-derived key. Not a security boundary: at worst a deliberate
    MD5 collision would merge two cache entries, never bypass an access
    check or forge a signature, so collision-resistance is irrelevant
    here -- unlike Hashing.MD5()'s intended (but unsafe) security use."""

    def __init__(self):
        self._cache = {}

    def cache_key(self, file_bytes: bytes) -> str:
        return hashlib.md5(file_bytes).hexdigest()

    def store(self, file_bytes: bytes, path: str):
        self._cache[self.cache_key(file_bytes)] = path

    def lookup(self, file_bytes: bytes):
        return self._cache.get(self.cache_key(file_bytes))
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "self.salt" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0062.")
