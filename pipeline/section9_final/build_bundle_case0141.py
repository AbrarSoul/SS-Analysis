"""
Section 9 ground-truth test bundle: CASE-0141
(datasharingframework/dsf, OidcClientWithCache.getAccessTokenDecoded,
CVE-2026-40942, CWE-670 always-incorrect control flow).

Core vulnerable mechanism: the access-token cache stores an entry whose
`timeout` is `expiresAt - cacheTimeoutAccessTokenBeforeExpiration` (the
moment the token should be refreshed). The lookup is inverted:
`accessTokenCache.timeout.isBefore(now)` returns the cached token exactly
when its refresh deadline has ALREADY PASSED, i.e. an expired (or nearly
expired) token keeps being served, while a still-valid entry is ignored and a
fresh token is fetched on every call. The upstream fix flips it to
`timeout.isAfter(now)`.

No sibling site: the configuration and JWKS caches in the same class already
use the correct `isAfter(now)` comparison, so nothing else needs fixing.

Every variant is the FULL real file with getAccessTokenDecoded(Configuration,
Jwks) replaced. It is an @Override of OidcClientWithDecodedJwt, so the renamed
variant renames parameters and locals, not the method.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0141"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "\tpublic DecodedJWT getAccessTokenDecoded(Configuration configuration, Jwks jwks) throws OidcClientException\n"
s = original.index(HDR)
e = original.index("\n\t}\n", s) + len("\n\t}\n")
BLOCK = original[s:e]
COND = "\t\tif (accessTokenCache != null && accessTokenCache.timeout.isBefore(ZonedDateTime.now()))\n"
assert original.count(HDR) == 1 and BLOCK.count(COND) == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


def rename(text, pairs):
    for old, new in pairs:
        text = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(old), new, text)
    return text


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("configuration", "oidcConfig"), ("jwks", "keySet"), ("accessToken", "token"), ("expiresAt", "expiry")))
assert "getAccessTokenDecoded(Configuration oidcConfig, Jwks keySet)" in b
assert "delegate.getAccessTokenDecoded(oidcConfig, keySet)" in b and "accessTokenCache.timeout.isBefore(" in b
assert "token.getExpiresAtAsInstant()" in b and "expiry.minus(" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(COND + "\t\t\treturn accessTokenCache.resource;\n\t\telse\n\t\t{\n", '''\t\tZonedDateTime now = ZonedDateTime.now();
\t\tCacheEntry<DecodedJWT> cached = accessTokenCache;
\t\tif (cached != null && cached.timeout.isBefore(now))
\t\t\treturn cached.resource;

\t\t{
''')
assert b != BLOCK and "cached.timeout.isBefore(now)" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Serve the cached token only while the time remaining until its refresh
# deadline is strictly positive (Duration.between(...).isPositive(), the same
# boundary as isAfter); upstream flips the comparison to isAfter(now).
b = BLOCK.replace(COND, '''\t\tCacheEntry<DecodedJWT> cached = accessTokenCache;
\t\tif (cached != null && Duration.between(ZonedDateTime.now(), cached.timeout).isPositive())
''').replace("\t\t\treturn accessTokenCache.resource;\n", "\t\t\treturn cached.resource;\n")
safe_source = build(b)
assert "isBefore" not in b and "return cached.resource;" in b and "accessTokenCache.resource" not in b
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.time.ZonedDateTime;
import java.util.function.Supplier;

public class RefreshingValue<T>
{
\\tprivate record Entry<T>(ZonedDateTime refreshAt, T value)
\\t{
\\t}

\\tprivate Entry<T> entry;

\\t/**
\\t * Same isBefore(now) comparison on a cache timeout as an access-token
\\t * cache, but used the correct way round: isBefore means the refresh
\\t * deadline has passed, so the entry is REPLACED, and only a deadline still
\\t * in the future is served from the cache.
\\t */
\\tpublic T get(Supplier<T> loader, ZonedDateTime newRefreshAt)
\\t{
\\t\\tif (entry == null || entry.refreshAt.isBefore(ZonedDateTime.now()))
\\t\\t{
\\t\\t\\tentry = new Entry<T>(newRefreshAt, loader.get());
\\t\\t}
\\t\\treturn entry.value;
\\t}
}
'''.replace("\\t", "\t")
assert "\\" not in benign_source and "entry.refreshAt.isBefore(" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0141.")
