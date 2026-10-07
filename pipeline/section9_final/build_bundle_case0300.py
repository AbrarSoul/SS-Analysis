"""
Section 9 ground-truth test bundle: CASE-0300
(theonedev/onedev, server-plugin/server-plugin-authenticator-ldap/src/main/
java/io/onedev/server/plugin/authenticator/ldap/LdapAuthenticator.java
authenticate, CVE-2021-32651, CWE-90 LDAP injection).

Core vulnerable mechanism: OneDev's LDAP authenticator finds the account
to bind as by substituting the login name into an administrator-configured
search filter template (default style `(uid={0})`):
`StringUtils.replace(getUserSearchFilter(), "{0}", token.getUsername())`,
then runs the resulting string as an LDAP search. The username is whatever
the person at the login form typed. LDAP filter syntax is not escaped, so a
username such as `*)(uid=*` or `admin)(|(uid=*` rewrites the filter's
structure (`(uid=*)(uid=*)`), matching arbitrary entries instead of the one
account: wildcard login / user enumeration, and, depending on the directory
and the rest of the flow, authentication as another user. The upstream fix
escapes the username per RFC 2254 (`*`, `(`, `)`, backslash and NUL become
`\2a`, `\28`, `\29`, `\5c`, `\00`) before substitution, using a table
copied from Spring LDAP's `LdapEncoder`.

Sibling sites: the filter is built at this single place in `authenticate`;
the backslash doubling that follows it is unrelated.

Verification: the two statements that build `userSearchFilter` (plus, for
the fixed variants, the `escape`/filter-table helper code the fix adds at
the end of the class) are extracted verbatim from each full file and
compiled with javac inside a harness class whose stand-ins are only
`StringUtils.replace` (plain string replace) and the `token`/
`getUserSearchFilter()` inputs (template `(uid={0})`). `build("*)(uid=*")`
returns the filter that would be sent to the directory: an unescaped
username adds extra `(`/`)` characters to the filter structure (more than
the template's single balanced pair), which is the injection. A benign
username `alice` must produce exactly `(uid=alice)` in every variant.

Every variant is the FULL real file. `authenticate` is called by name by the
security realm, so its name/signature are kept (the renamed variant
renames only the local filter variable, not the same-named field).
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0300"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


L184 = '        String userSearchFilter = StringUtils.replace(getUserSearchFilter(), "{0}", token.getUsername());\n'
L185 = '        userSearchFilter = StringUtils.replace(userSearchFilter, "\\\\", "\\\\\\\\");\n'
L186 = '        logger.debug("Evaluated user search filter: " + userSearchFilter);\n'
L226 = 'ctx.search(userSearchBase, userSearchFilter, searchControls);'
for x in (L184, L185, L186, L226):
    assert original.count(x) == 1, x

# --- Variant 1: renamed vulnerable variant (the LOCAL only, not the same-named field) ---
v1 = swap(original, L184, '        String ldapFilter = StringUtils.replace(getUserSearchFilter(), "{0}", token.getUsername());\n')
v1 = swap(v1, L185, '        ldapFilter = StringUtils.replace(ldapFilter, "\\\\", "\\\\\\\\");\n')
v1 = swap(v1, L186, '        logger.debug("Evaluated user search filter: " + ldapFilter);\n')
v1 = swap(v1, L226, 'ctx.search(userSearchBase, ldapFilter, searchControls);')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, L184, '        String userSearchFilter = buildSearchFilter(token.getUsername());\n')
v2 = swap(v2, "\tpublic boolean isManagingSshKeys() {", '''	private String buildSearchFilter(String username) {
		return StringUtils.replace(getUserSearchFilter(), "{0}", username);
	}

	public boolean isManagingSshKeys() {''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, escape() re-implemented) ---
ps = patched.index("    private static String escape(String value) {")
pe = patched.index("        return encodedValue.toString();\n    }", ps) + len("        return encodedValue.toString();\n    }")
v3 = patched[:ps] + '''    private static String escape(String value) {
        // RFC 2254 filter escaping: * ( ) \\ and NUL
        StringBuilder out = new StringBuilder(value.length() * 2);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '*': out.append("\\\\2a"); break;
                case '(': out.append("\\\\28"); break;
                case ')': out.append("\\\\29"); break;
                case '\\\\': out.append("\\\\5c"); break;
                case 0: out.append("\\\\00"); break;
                default: out.append(c);
            }
        }
        return out.toString();
    }''' + patched[pe:]
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package io.onedev.server.plugin.authenticator.ldap;

/**
 * Standalone example of the same shape: substitute a value into a template,
 * but the template is a plain log line (never an LDAP filter or any
 * query language), so no escaping is needed.
 */
class LogLineTemplate {

    static String render(String template, String user) {
        return template.replace("{0}", user);
    }
}
''')
