"""
Section 9 ground-truth test bundle: CASE-0185
(jenkinsci/google-login-plugin, .../googlelogin/OAuthSession.java
doFinishLogin, CVE-2023-41936, CWE-697 incorrect comparison / timing side
channel on a secret).

Core vulnerable mechanism: the OAuth `state` value that binds the login
response to the session (a CSRF/anti-forgery token) is compared with
`uuid.equals(responseUrl.getState())`. `String.equals` returns at the first
differing character, so the response time of the callback depends on how much
of a guessed state is correct, letting an attacker recover the token
character by character. The upstream fix compares the UTF-8 bytes with
`MessageDigest.isEqual` (constant time) and rejects a null state.

Verification note: a comparison-time difference cannot be observed reliably
on a 20-character token in a unit test, so the runtime check is functional
(a matching state completes the login, a wrong, empty or missing state gives
401 in every variant); the timing property is stated by the code, not
measured. The file is compiled with the real google-oauth-client jar and
small stand-ins for the Jenkins/Stapler classes.

Sibling sites: none in this file (the state is compared once).

Every variant is the FULL real file. doFinishLogin is bound by name by
Stapler, so the renamed variant keeps the method name and renames its
parameter and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0185"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

CMP = '''            if (! uuid.equals(responseUrl.getState())) {
                return HttpResponses.error(401, "State is invalid");
            }
'''
s = original.index("    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {\n")
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert BLOCK.count(CMP) == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
parts = re.split(r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')', BLOCK)
for i in range(0, len(parts), 2):
    for old, new in (("request", "req"), ("buf", "callbackUrl"), ("responseUrl", "parsed"), ("code", "authCode"), ("e", "ex")):
        parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
b = "".join(parts)
assert "doFinishLogin(StaplerRequest req)" in b and "if (! uuid.equals(parsed.getState())) {" in b
assert "return onSuccess(authCode);" in b and "catch (IllegalArgumentException ex)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(CMP, '''            if (!stateMatches(responseUrl.getState())) {
                return HttpResponses.error(401, "State is invalid");
            }
''')
helper = '''
    private boolean stateMatches(String presented) {
        return uuid.equals(presented);
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Both values are hashed with SHA-256 and the digests compared with the
# constant-time MessageDigest.isEqual (so the lengths do not leak either);
# upstream compares the raw UTF-8 bytes with isEqual.
b = BLOCK.replace(CMP, '''            String state = responseUrl.getState();
            if (state == null || !sameSecret(uuid, state)) {
                return HttpResponses.error(401, "State is invalid");
            }
''')
helper = '''
    private static boolean sameSecret(String expected, String presented) {
        try {
            java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
            byte[] a = sha.digest(expected.getBytes(StandardCharsets.UTF_8));
            byte[] c = sha.digest(presented.getBytes(StandardCharsets.UTF_8));
            return java.security.MessageDigest.isEqual(a, c);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
'''
(CASE_DIR / "variant_safe_01.java").write_text(build(b, extra_after=helper))

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.util.Locale;

public class LocalePreference {

    /**
     * Same String.equals comparison as the state check, but on non-secret
     * values (two language tags shown in the UI), so how long the comparison
     * takes reveals nothing an attacker could not already read.
     */
    public static boolean sameLanguage(String requested, String configured) {
        return requested.toLowerCase(Locale.ROOT).equals(configured.toLowerCase(Locale.ROOT));
    }
}
'''
assert "non-secret" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0185.")
