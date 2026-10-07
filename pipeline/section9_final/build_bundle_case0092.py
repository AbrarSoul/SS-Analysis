"""
Section 9 ground-truth test bundle: CASE-0092
(airsonic/airsonic, CVE-2019-10907, CWE-326 inadequate encryption
strength / hard-coded remember-me key).

Core vulnerable mechanism: the Spring Security remember-me service is
configured with a HARD-CODED, publicly known key --
`.rememberMe().key("airsonic")`. The remember-me cookie's signature is
derived from that key, so anyone who knows it (it is in the open-source
repository) can forge a valid remember-me cookie for any user and log in
as them. The upstream fix generates a random key at startup with
SecureRandom in a static initializer.

`configure(HttpSecurity)` is a Spring override and cannot be renamed, so
the renamed variant renames the parameter and locals of the second
configure() (WebSecurityConfiguration) only.

Every variant is the FULL real file with the second configure() (or the
key it uses) replaced.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0092"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.java").read_text().splitlines()) + "\n"

SIG = "        protected void configure(HttpSecurity http) throws Exception {"
first = original.index(SIG)
s = original.index(SIG, first + 1)  # the SECOND configure (WebSecurityConfiguration)
END_MARK = '.and().rememberMe().key("airsonic");\n        }\n'
e = original.index(END_MARK, s) + len(END_MARK)
BLOCK = original[s:e]
assert original.count(SIG) == 2 and original.count('.key("airsonic")') == 1


def build(new_block, text=None):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = re.sub(r"\bhttp\b(?!:)", "security", BLOCK)
b = re.sub(r"\brestAuthenticationFilter\b", "restFilter", b)
assert '.key("airsonic")' in b and "http://" in b or "http" not in re.sub(r"http://\S+", "", b)
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(SIG + "\n", SIG + '\n            final String rememberMeKey = "airsonic";\n', 1)
b = b.replace('.key("airsonic")', ".key(rememberMeKey)")
assert 'final String rememberMeKey = "airsonic";' in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Random 256-bit key generated once at startup (Base64 of SecureRandom bytes)
# with an optional environment override for multi-node deployments, instead
# of upstream's inline static initializer producing new String(randomBytes).
HELPER = '''    static final String FAILURE_URL = "/login?error=1";

    private static final String key = generateRememberMeKey();

    private static String generateRememberMeKey() {
        String configured = System.getenv("AIRSONIC_REMEMBER_ME_KEY");
        if (configured != null && configured.length() >= 32) {
            return configured;
        }
        byte[] random = new byte[32];
        new java.security.SecureRandom().nextBytes(random);
        return java.util.Base64.getEncoder().encodeToString(random);
    }
'''
assert original.count('    static final String FAILURE_URL = "/login?error=1";\n') == 1
safe = build(BLOCK.replace('.key("airsonic")', ".key(key)"))
safe = safe.replace('    static final String FAILURE_URL = "/login?error=1";\n', HELPER, 1)
assert ".key(key)" in safe and "generateRememberMeKey" in safe
(CASE_DIR / "variant_safe_01.java").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.java").write_text('''public class MetricNames {

    // The same literal "airsonic" appears here, but purely as a public metrics
    // name prefix. It is not a secret and nothing security-relevant (no
    // signing, no cookie, no authentication) is derived from it.
    private static final String PREFIX = "airsonic";

    public static String loginCounter() {
        return PREFIX + ".login.count";
    }

    public static String streamTimer() {
        return PREFIX + ".stream.time";
    }
}
''')
print("Wrote 4 new samples for CASE-0092.")
