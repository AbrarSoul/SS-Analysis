"""
Section 9 ground-truth test bundle: CASE-0182
(jenkinsci/aws-device-farm-plugin, AWSDeviceFarmRecorder.java
validateConfiguration and the credential fields, CVE-2019-1003064,
CWE-311 missing encryption of sensitive data).

Located target: `private boolean validateConfiguration(@Nonnull PrintStream log) {`.

Core vulnerable mechanism: the plugin's global configuration keeps the AWS
access key id and secret key as plain `String` fields of its descriptor
(`public String akid; public String skid;`) and returns them from
`getAkid()` / `getSkid()`. Jenkins persists descriptor fields with XStream into
config.xml, so the secret key is written to disk in CLEAR TEXT, unlike a
`hudson.util.Secret` field, which is stored encrypted with the instance key.
`validateConfiguration` reads the plain getters. The upstream fix changes the
two fields and their getters to `Secret`, converts in the setters
(`Secret.fromString`) and at every read (`Secret.toString`).

Sibling sites: the fix is spread over the file: the descriptor fields, the two
getters, the two setters, `validateConfiguration`, the descriptor's connection
and form-validation methods (`doCheckAkid`, `doCheckSkid`, and two more that read
the fields) and the `BasicAWSCredentials` construction. The safe variant
applies the same conversion at ALL those sites (with a small `plainText`
helper instead of Secret.toString); the vulnerable variants leave them all.

Verification: this file cannot be compiled or run standalone (Jenkins core,
the AWS SDK and the device farm client are not on the classpath), and the
XStream/config.xml behaviour depends on the Jenkins runtime; every variant is
checked with the repository's syntax-only javac wrapper. This is the weakest
level of verification used in Section 9.

Every variant is the FULL real file.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0182"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original and "\r" not in patched

s = original.index("    private boolean validateConfiguration(@Nonnull PrintStream log) {\n")
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CRED = '''        if ((roleArn == null || roleArn.isEmpty()) && (akid == null || akid.isEmpty() || skid == null || skid.isEmpty())) {
            writeToLog(log, "Either IAM Role ARN or AKID/SKID must be set.");
            return false;
        }
'''
assert BLOCK.count(CRED) == 1


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith(("//", "*", "/*")):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("roleArn", "arn"), ("akid", "accessKeyId"), ("skid", "secretKeyId")))
assert "String accessKeyId = getAkid();" in b and "String secretKeyId = getSkid();" in b
assert "(arn == null || arn.isEmpty()) && (accessKeyId == null" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(CRED, '''        if (!hasAuthCredentials(roleArn, akid, skid)) {
            writeToLog(log, "Either IAM Role ARN or AKID/SKID must be set.");
            return false;
        }
''')
helper = '''
    private static boolean hasAuthCredentials(String roleArn, String akid, String skid) {
        boolean hasRole = roleArn != null && !roleArn.isEmpty();
        boolean hasKeys = akid != null && !akid.isEmpty() && skid != null && !skid.isEmpty();
        return hasRole || hasKeys;
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# The upstream conversion (Secret fields, getters, setters, every read),
# expressed with a private plainText() helper instead of Secret.toString.
v3 = patched.replace("Secret.toString(", "plainText(")
assert v3.count("plainText(") >= 10 and "Secret.fromString(" in v3 and "public Secret akid;" in v3
anchor = "    private boolean validateConfiguration(@Nonnull PrintStream log) {\n"
assert v3.count(anchor) == 1
v3 = v3.replace(anchor, '''    private static String plainText(Secret secret) {
        return secret == null ? null : secret.getPlainText();
    }

''' + anchor)
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import hudson.util.Secret;

public class TokenHolder {

    private final Secret token;

    public TokenHolder(String plainToken) {
        this.token = Secret.fromString(plainToken);
    }

    /**
     * Same "hold a credential and expose it to callers" shape as the recorder's
     * key fields, but the value is a hudson.util.Secret, so Jenkins stores it
     * encrypted and the text form never reaches config.xml.
     */
    public Secret getToken() {
        return token;
    }
}
'''
assert "hudson.util.Secret" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0182.")
