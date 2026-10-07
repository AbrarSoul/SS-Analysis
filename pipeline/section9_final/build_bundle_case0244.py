"""
Section 9 ground-truth test bundle: CASE-0244
(opencast/opencast, modules/kernel/src/main/java/org/opencastproject/kernel/
security/SecurityServiceSpringImpl.java getUser, CVE-2020-5206, CWE-285 /
CWE-287 improper authorisation, identity confusion).

Core vulnerable mechanism: `getUser()` returns `delegatedUserHolder.get()` first,
before it looks at the Spring Security context, and, after resolving an
authenticated user from the context, it "saves the user to retrieve it quicker
the next time" by writing it into that same `ThreadLocal`
(`delegatedUserHolder.set(user)`). The holder is never cleared for ordinary web
requests, and servlet containers reuse threads: the next request served by the same
thread, even an ANONYMOUS one (Spring's `AnonymousAuthenticationToken`), finds a
non-null delegated user and gets the previous request's identity and roles back
(for example an administrator). The upstream fix reads the authentication first and
returns `SecurityUtil.createAnonymousUser(org)` when it is an
`AnonymousAuthenticationToken`, before the delegated user is consulted.

Measured caveat, kept in the manifest notes: the upstream check covers only an
`AnonymousAuthenticationToken`; when the next request has NO authentication at all
(`auth == null`) the stale cached user is still returned, and the ThreadLocal is
still written after every authenticated call. The safe variant keeps the anonymous
check and also stops caching the resolved user in `delegatedUserHolder` (explicit
`setUser` delegation for spawned job threads is unchanged).

Sibling sites: `setUser` writes the holder on purpose (explicit delegation), and
`getUser` is the only place that caches an authenticated user in it.

Verification: each full SecurityServiceSpringImpl.java is COMPILED with javac against the
REAL Spring Security 4.2.13 (`SecurityContextHolder`, `AnonymousAuthenticationToken`,
`UserDetails`) and slf4j jars plus minimal stand-ins for the Opencast API types it
imports (Organization, User, JaxbUser, JaxbRole, JaxbOrganization, SecurityService,
UserDirectoryService, SecurityUtil). One thread runs: (1) an authenticated admin
request, (2) an anonymous request, (3) a request with no authentication.

Every variant is the FULL real file. `getUser` implements `SecurityService.getUser`, so its
name and signature are kept; the renamed variant renames locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0244"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


HEAD = '''    Organization org = getOrganization();
    if (org == null)
      throw new IllegalStateException("No organization is set in security context");

    User delegatedUser = delegatedUserHolder.get();

    if (delegatedUser != null) {
      return delegatedUser;
    }

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(org);
'''
assert original.count(HEAD) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("  public User getUser() throws IllegalStateException {")
e = original.index("  /**\n   * {@inheritDoc}\n   *\n   * @see org.opencastproject.security.api.SecurityService#setUser(User)")
seg = original[s:e]
import re
for a, b in (("delegatedUser", "cachedUser"), ("jaxbOrganization", "jaxbOrg"), ("auth", "authentication"), ("org", "currentOrg")):
    seg = re.sub(r"(?<![\w.])%s\b(?!\()" % a, b, seg) if a in ("auth", "org") else re.sub(r"\b%s\b" % a, b, seg)
assert "cachedUser" in seg and "authentication" in seg and "currentOrg" in seg and "delegatedUserHolder" in seg
v1 = original[:s] + seg + original[e:]
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
CACHE = '''        // Save the user to retrieve it quicker the next time(s) this method is called (by this thread)
        delegatedUserHolder.set(user);

        return user;
'''
assert original.count(CACHE) == 1
v2 = swap(original, CACHE, '''        return remember(user);
''')
v2 = swap(v2, "  /**\n   * {@inheritDoc}\n   *\n   * @see org.opencastproject.security.api.SecurityService#setUser(User)", '''  private static User remember(User user) {
    // Save the user to retrieve it quicker the next time(s) this method is called (by this thread)
    delegatedUserHolder.set(user);
    return user;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.opencastproject.security.api.SecurityService#setUser(User)''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "import org.springframework.security.core.Authentication;\n",
          "import org.springframework.security.authentication.AnonymousAuthenticationToken;\nimport org.springframework.security.core.Authentication;\n")
v3 = swap(v3, HEAD, '''    Organization org = getOrganization();
    if (org == null)
      throw new IllegalStateException("No organization is set in security context");

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(org);
    if (auth instanceof AnonymousAuthenticationToken) {
      return SecurityUtil.createAnonymousUser(jaxbOrganization);
    }

    User delegatedUser = delegatedUserHolder.get();
    if (delegatedUser != null) {
      return delegatedUser;
    }

''')
v3 = swap(v3, CACHE, '''        // Do not cache the resolved user in the thread-local: a pooled thread would hand it to the next request.
        return user;
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

BENIGN = '''package org.opencastproject.kernel.security;

/**
 * Standalone example of the same shape: a per-thread value that IS cleared in a
 * finally block after each unit of work, so a pooled thread never leaks it into
 * the next request.
 */
public class RequestLocal<T> {

    private final ThreadLocal<T> holder = new ThreadLocal<>();

    public T runWith(T value, java.util.function.Function<T, T> work) {
        holder.set(value);
        try {
            return work.apply(holder.get());
        } finally {
            holder.remove();
        }
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)
