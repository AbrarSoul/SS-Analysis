"""
Section 9 ground-truth test bundle: CASE-0294
(spring-projects/spring-framework, spring-web/src/main/java/org/
springframework/web/util/UriComponentsBuilder.java, CVE-2024-22259,
CWE-601 URL redirection to an untrusted site / open redirect and SSRF).

Core vulnerable mechanism: applications commonly validate a user-supplied
redirect/target URL by parsing it with `UriComponentsBuilder.fromUriString`
(or `fromHttpUrl`) and checking `getHost()` against an allow-list. Spring's
own URL regex disagrees with real URL parsers about where userinfo ends:
`USERINFO_PATTERN` is `([^@/?#]*)` (userinfo may not contain `@`) and
`HOST_IPV4_PATTERN` is a host class that excludes an opening square bracket,
so for `https://user@allowed.com[@evil.com` the regex takes `allowed.com` as
the HOST, while browsers/HTTP clients (WHATWG/RFC 3986 parsing: userinfo runs
to the LAST `@`) read `user@allowed.com[` as userinfo and `evil.com` as the
host. The allow-list check passes on `allowed.com`; the redirect/request
then goes to `evil.com` (open redirect / SSRF). The upstream fix relaxes
both patterns (userinfo `([^/?#]*)`, host class `[^/?#:]*`) so userinfo runs
to the last `@` like real parsers, and adds `checkSchemeAndHost` to reject a
host that starts with an opening bracket but is not a well-formed IPv6
literal, applied in `fromUriString`, `fromHttpUrl` and `fromOriginHeader`.

Sibling sites: the same regexes and scheme/host check gap are used by
`fromUriString`, `fromHttpUrl` and `fromOriginHeader`; the fix (and the
safe variant, built from the real patched file) covers all three.

Verification: each FULL file is compiled with javac (JDK 26) as a
replacement for `UriComponentsBuilder` against the REAL `spring-web`,
`spring-core`, `spring-jcl` and `spring-beans` 6.1.3 jars from Maven
Central and driven through the public API. The parsed host of
`https://example.com[@attacker.com` is read via `fromUriString(...).build()
.getHost()` and via `fromHttpUrl`; a host of `allowed.com` (what an
allow-list would see) is the vulnerable behaviour, while `evil.com` (the
real destination) or a rejection is correct. Controls:
`https://allowed.com/path` must parse to host `allowed.com` in every variant,
and `https://user@allowed.com` must keep `allowed.com` as its host.

Every variant is the FULL real file. `UriComponentsBuilder` is a public
Spring API used by name everywhere, so it is kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0294"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (regex constants) ---
v1 = re.sub(r"\bUSERINFO_PATTERN\b", "USER_INFO_REGEX", original)
v1 = re.sub(r"\bHOST_IPV4_PATTERN\b", "HOST_NAME_REGEX", v1)
assert v1 != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, 'private static final String USERINFO_PATTERN = "([^@/?#]*)";',
          'private static final String USERINFO_PATTERN = userInfoPattern();')
v2 = swap(v2, 'private static final String HOST_IPV4_PATTERN = "[^\\\\[/?#:]*";',
          'private static final String HOST_IPV4_PATTERN = hostPattern();')
v2 = swap(v2, "\tprivate static final String HTTP_PATTERN =", '''	private static String userInfoPattern() {
		return "([^@/?#]*)";
	}

	private static String hostPattern() {
		return "[^\\\\[/?#:]*";
	}

	private static final String HTTP_PATTERN =''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, helper split in two) ---
CHK = '''	private static void checkSchemeAndHost(String uri, @Nullable String scheme, @Nullable String host) {
		if (StringUtils.hasLength(scheme) && scheme.startsWith("http") && !StringUtils.hasLength(host)) {
			throw new IllegalArgumentException("[" + uri + "] is not a valid HTTP URL");
		}
		if (StringUtils.hasLength(host) && host.startsWith("[") && !host.endsWith("]")) {
			throw new IllegalArgumentException("Invalid IPV6 host in [" + uri + "]");
		}
	}
'''
assert patched.count(CHK) == 1
v3 = swap(patched, CHK, '''	private static void checkSchemeAndHost(String uri, @Nullable String scheme, @Nullable String host) {
		requireHostForHttp(uri, scheme, host);
		requireWellFormedIpv6Host(uri, host);
	}

	private static void requireHostForHttp(String uri, @Nullable String scheme, @Nullable String host) {
		if (StringUtils.hasLength(scheme) && scheme.startsWith("http") && !StringUtils.hasLength(host)) {
			throw new IllegalArgumentException("[" + uri + "] is not a valid HTTP URL");
		}
	}

	private static void requireWellFormedIpv6Host(String uri, @Nullable String host) {
		if (StringUtils.hasLength(host) && host.startsWith("[") && !host.endsWith("]")) {
			throw new IllegalArgumentException("Invalid IPV6 host in [" + uri + "]");
		}
	}
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package org.springframework.web.util;

/**
 * Standalone example of the same shape: pull the file extension out of a path
 * with a permissive regex for a MIME-type hint; the value is only used for a
 * content-type guess, never for an allow-list or redirect decision.
 */
final class ExtensionHint {

    private ExtensionHint() {
    }

    static String of(String path) {
        int dot = path.lastIndexOf('.');
        return dot < 0 ? "" : path.substring(dot + 1);
    }
}
''')
