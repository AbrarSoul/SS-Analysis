import hashlib


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
