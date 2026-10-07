"""
Section 9 ground-truth test bundle: CASE-0093
(airsonic/airsonic, CVE-2019-10908, CWE-335 incorrect use of a PRNG seed /
weak password-reset randomness).

Core vulnerable mechanism: the password-reset flow generates the new
password with `RandomStringUtils.randomAlphanumeric(8)`. That commons-lang
helper draws from java.util.Random (a non-cryptographic 48-bit LCG seeded
from the clock), and 8 characters give only ~47 bits at best, so the
generated password can be predicted or brute-forced by an attacker who can
trigger a reset for a chosen account. The upstream fix generates a
32-character password from java.security.SecureRandom.

Every variant is the FULL real file with RecoverController.recover
replaced. `recover` is bound by @RequestMapping (not by name), so it may be
renamed safely.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0093"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.java").read_text().splitlines()) + "\n"

START = "    public ModelAndView recover(HttpServletRequest request, HttpServletResponse response) throws Exception {"
END_MARK = '        return new ModelAndView("recover", "model", map);\n    }\n'
s = original.index(START)
e = original.index(END_MARK, s) + len(END_MARK)
BLOCK = original[s:e]
assert original.count(START) == 1
assert "RandomStringUtils.randomAlphanumeric(8)" in BLOCK and original.count("recover(") == 1


def build(new_block, text=None):
    assert new_block != BLOCK
    return (text or original)[:s] + new_block + (text or original)[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("ModelAndView recover(", "ModelAndView handleRecovery(")
for old, new in (("request", "httpRequest"), ("response", "httpResponse"), ("map", "viewModel"),
                 ("password", "newPassword"), ("captchaOk", "captchaPassed")):
    b = re.sub(r'(?<!")\b%s\b(?!")' % old, new, b)
assert "RandomStringUtils.randomAlphanumeric(8)" in b and "handleRecovery" in b
assert 'getParameter("usernameOrEmail")' in b  # string literals untouched
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(
    "                String password = RandomStringUtils.randomAlphanumeric(8);\n",
    "                final int passwordLength = 8;\n"
    "                String password = RandomStringUtils.randomAlphanumeric(passwordLength);\n")
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# 160 bits from a static SecureRandom rendered in base 36 via BigInteger
# (pure JDK), instead of upstream's 32-character SYMBOLS loop; the now
# unused RandomStringUtils import is dropped.
b = BLOCK.replace("                String password = RandomStringUtils.randomAlphanumeric(8);\n",
                  "                String password = new java.math.BigInteger(160, SECURE_RANDOM).toString(36);\n")
safe = build(b)
field_anchor = "    private static final Logger LOG = LoggerFactory.getLogger(RecoverController.class);\n"
assert safe.count(field_anchor) == 1
safe = safe.replace(field_anchor, field_anchor + "\n    private static final java.security.SecureRandom SECURE_RANDOM = new java.security.SecureRandom();\n")
imp = "import org.apache.commons.lang.RandomStringUtils;\n"
assert safe.count(imp) == 1
safe = safe.replace(imp, "")
assert "RandomStringUtils" not in safe and "SECURE_RANDOM" in safe
(CASE_DIR / "variant_safe_01.java").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.java").write_text('''import java.util.Random;

public class WidgetIds {

    private static final String SYMBOLS = "abcdefghijklmnopqrstuvwxyz0123456789";
    private final Random random = new Random();

    /**
     * Same "random alphanumeric string" shape, but only used to build a
     * cosmetic DOM element id for the UI. It is not a credential or token, an
     * attacker gains nothing by predicting it, so a non-cryptographic Random
     * is appropriate here.
     */
    public String nextElementId() {
        StringBuilder sb = new StringBuilder("widget-");
        for (int i = 0; i < 8; i++) {
            sb.append(SYMBOLS.charAt(random.nextInt(SYMBOLS.length())));
        }
        return sb.toString();
    }
}
''')
print("Wrote 4 new samples for CASE-0093.")
