"""
Section 9 ground-truth test bundle: CASE-0297
(spring-projects/spring-session, spring-session-core/src/main/java/org/
springframework/session/web/http/HeaderHttpSessionIdResolver.java
resolveSessionIds, CVE-2023-20866, CWE-200 exposure of sensitive
information / session-identifier disclosure in logs).

Core vulnerable mechanism: `HeaderHttpSessionIdResolver` reads the session
id from a request header (e.g. `X-Auth-Token`, the resolver used by REST
APIs). Left over from debugging, `resolveSessionIds` calls
`System.out.println(headerValue)` on EVERY request, writing the raw session
id -- the bearer credential for that session -- to standard output. Standard
output is collected by container runtimes, log shippers and process
supervisors, so anyone with read access to application logs (operators,
log-aggregation users, a compromised logging backend, support engineers)
can copy live session ids from them and hijack those sessions. The upstream
fix simply deletes the `System.out.println`.

Sibling sites: the file has no other logging of the header value.

Verification: each FULL file is compiled with javac (JDK 26) as a
replacement for `HeaderHttpSessionIdResolver` against the REAL
`spring-session-core` 3.0.0, `spring-core`/`spring-jcl` 6.0.2 and
`jakarta.servlet-api` 6.0.0 jars from Maven Central. `resolveSessionIds` is
called with a `java.lang.reflect.Proxy` implementing the real
`HttpServletRequest` interface whose `getHeader` returns the secret
`SESSION-ABC-SECRET`, with `System.out` redirected to a buffer: whether the
secret appears in the captured standard output is the measurement. The
returned id list must still be `[SESSION-ABC-SECRET]` (and empty for an
absent header) in every variant.

Every variant is the FULL real file. `resolveSessionIds` implements the
`HttpSessionIdResolver` interface by name, so its name/signature are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0297"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


BODY = '''		String headerValue = request.getHeader(this.headerName);
		System.out.println(headerValue);
		return (headerValue != null) ? Collections.singletonList(headerValue) : Collections.emptyList();
'''
assert original.count(BODY) == 1

v1 = swap(original, BODY, '''		String sessionHeader = request.getHeader(this.headerName);
		System.out.println(sessionHeader);
		return (sessionHeader != null) ? Collections.singletonList(sessionHeader) : Collections.emptyList();
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

v2 = swap(original, BODY, '''		String headerValue = readHeader(request);
		return (headerValue != null) ? Collections.singletonList(headerValue) : Collections.emptyList();
''')
v2 = swap(v2, "\t@Override\n\tpublic void setSessionId(", '''	private String readHeader(HttpServletRequest request) {
		String value = request.getHeader(this.headerName);
		System.out.println(value);
		return value;
	}

	@Override
	public void setSessionId(''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

PBODY = '''		String headerValue = request.getHeader(this.headerName);
		return (headerValue != null) ? Collections.singletonList(headerValue) : Collections.emptyList();
'''
assert patched.count(PBODY) == 1
v3 = swap(patched, PBODY, '''		String headerValue = request.getHeader(this.headerName);
		if (headerValue == null) {
			return Collections.emptyList();
		}
		return Collections.singletonList(headerValue);
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package org.springframework.session.web.http;

/**
 * Standalone example of the same shape: print the (public) application
 * version to standard output once at startup, a value that is not a
 * credential and is meant to appear in logs.
 */
class StartupBanner {

    static void printVersion(String version) {
        System.out.println("Application version " + version);
    }
}
''')
