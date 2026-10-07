"""
Section 9 ground-truth test bundle: CASE-0296
(spring-projects/spring-ldap, core/src/main/java/org/springframework/ldap/
core/support/DefaultTlsDirContextAuthenticationStrategy.java
applyAuthentication, CVE-2017-8028, CWE-287 improper authentication).

Core vulnerable mechanism: with TLS-based LDAP authentication, Spring LDAP
first starts TLS on an (initially anonymous) connection and then calls
`applyAuthentication` to log in as the requesting user. Setting
`Context.SECURITY_AUTHENTICATION`, `SECURITY_PRINCIPAL` and
`SECURITY_CREDENTIALS` with `ctx.addToEnvironment(...)` only updates the
context's ENVIRONMENT PROPERTIES: JNDI documents that changes to these
security properties take effect only on the next (re)connection
(`LdapContext.reconnect`). The vulnerable method never reconnects, so the
connection keeps its anonymous bind while the code believes it is
authenticated as `userDn`. Spring LDAP's `authenticate(...)` (used for
application logins) then succeeds for ANY password, since the check
"opens a context with these credentials" and it never actually tries them:
an attacker who knows a valid username logs in with an arbitrary password
(authentication bypass, in servers that allow anonymous bind). The upstream
fix adds `ctx.reconnect(null)` after setting the credentials.

Sibling sites: `applyAuthentication` is the strategy hook implemented once
per authentication style; this class is the one that applies SIMPLE auth.

Verification: each FULL file is compiled with javac (JDK 26) into package
`org.springframework.ldap.core.support` against the REAL `spring-ldap-core`
2.3.1.RELEASE jar (plus `spring-tx`, `spring-beans`, `spring-core`) as a
replacement for the class, and its (protected) `applyAuthentication` is
called from a test class in the same package on a `java.lang.reflect.Proxy`
implementing the real JDK `javax.naming.ldap.LdapContext` interface that
records every `addToEnvironment` and `reconnect` call in order. The
property checked is that a `reconnect` call happens AFTER the credentials
were set (the only point at which they are actually used to bind).

Every variant is the FULL real file. `applyAuthentication` is a protected
template hook called by name from the abstract strategy, so its name/signature
are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0296"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


BODY = '''	protected void applyAuthentication(LdapContext ctx, String userDn, String password) throws NamingException {
		ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION);
		ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, userDn);
		ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
	}
'''
assert original.count(BODY) == 1

v1 = swap(original, BODY, '''	protected void applyAuthentication(LdapContext context, String bindDn, String secret) throws NamingException {
		context.addToEnvironment(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION);
		context.addToEnvironment(Context.SECURITY_PRINCIPAL, bindDn);
		context.addToEnvironment(Context.SECURITY_CREDENTIALS, secret);
	}
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

v2 = swap(original, BODY, '''	protected void applyAuthentication(LdapContext ctx, String userDn, String password) throws NamingException {
		setSimpleCredentials(ctx, userDn, password);
	}

	private void setSimpleCredentials(LdapContext ctx, String userDn, String password) throws NamingException {
		ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION);
		ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, userDn);
		ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
	}
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

v3 = swap(original, BODY, '''	protected void applyAuthentication(LdapContext ctx, String userDn, String password) throws NamingException {
		setSimpleCredentials(ctx, userDn, password);
		rebindWithCredentials(ctx);
	}

	private void setSimpleCredentials(LdapContext ctx, String userDn, String password) throws NamingException {
		ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, SIMPLE_AUTHENTICATION);
		ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, userDn);
		ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
	}

	/** The security properties only take effect on a (re)connect. */
	private void rebindWithCredentials(LdapContext ctx) throws NamingException {
		ctx.reconnect(null);
	}
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package org.springframework.ldap.core.support;

import java.util.Map;

/**
 * Standalone example of the same shape: set display-only properties on a
 * settings map (a UI theme and title) with no need to re-open any
 * connection for them to take effect.
 */
class DisplaySettings {

    static void apply(Map<String, String> settings, String theme, String title) {
        settings.put("theme", theme);
        settings.put("title", title);
    }
}
''')
