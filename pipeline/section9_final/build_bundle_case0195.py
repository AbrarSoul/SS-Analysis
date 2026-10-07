"""
Section 9 ground-truth test bundle: CASE-0195
(jenkinsci/subversion-plugin, src/main/java/hudson/scm/SubversionSCM.java
PasswordCredential.createSVNAuthentication and the sibling credential
classes, CVE-2013-6372, CWE-255 credentials management).

Located target: `public SVNAuthentication createSVNAuthentication(String kind)`
of `PasswordCredential`.

Core vulnerable mechanism: the plugin stores Subversion passwords and
key passphrases in credential objects that Jenkins persists (XStream /
Java serialization, in credentials.xml) as `private final String password;
// scrambled by base64`. `Scrambler.scramble` is only Base64, an encoding
anyone can reverse, so the stored value is effectively the clear-text
password. The upstream fix wraps the value in `hudson.util.Secret` (encrypted
with the instance key) for PasswordCredential, SshPublicKeyCredential and
SslClientCertificateCredential, keeping the Base64 step "for historical
reasons".

Sibling sites: three credential classes hold a scrambled String (PasswordCredential.password,
SshPublicKeyCredential.passphrase, SslClientCertificateCredential.password);
the safe variant converts all three and every read (createSVNAuthentication
in each), the vulnerable variants leave all three.

Verification: syntax-only (pipeline/check_java_syntax.sh). SubversionSCM
needs Jenkins core and SVNKit; how Jenkins serialises a Secret field versus a
String field is a Jenkins runtime behaviour that was not run. This is the
weakest verification level used in Section 9.

Every variant is the FULL real file. createSVNAuthentication overrides
Credential's abstract method, so the renamed variant keeps its name and renames
its parameter.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0195"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original and "\r" not in patched

CREATE = '''            @Override
            public SVNAuthentication createSVNAuthentication(String kind) {
                if(kind.equals(ISVNAuthenticationManager.SSH))
                    return new SVNSSHAuthentication(userName,Scrambler.descramble(password),-1,false);
                else
                    return new SVNPasswordAuthentication(userName,Scrambler.descramble(password),false);
            }
'''
assert original.count(CREATE) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, CREATE, '''            @Override
            public SVNAuthentication createSVNAuthentication(String scheme) {
                if(scheme.equals(ISVNAuthenticationManager.SSH))
                    return new SVNSSHAuthentication(userName,Scrambler.descramble(password),-1,false);
                else
                    return new SVNPasswordAuthentication(userName,Scrambler.descramble(password),false);
            }
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CREATE, '''            @Override
            public SVNAuthentication createSVNAuthentication(String kind) {
                String clear = clearPassword();
                if(kind.equals(ISVNAuthenticationManager.SSH))
                    return new SVNSSHAuthentication(userName,clear,-1,false);
                else
                    return new SVNPasswordAuthentication(userName,clear,false);
            }

            private String clearPassword() {
                return Scrambler.descramble(password);
            }
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The upstream Secret conversion at every site, with the reads going through a
# small static plainText(Secret) helper defined once in the Credential base
# class instead of Secret.toString(...) at each site.
v3 = patched.replace("Secret.toString(", "plainText(")
assert v3.count("plainText(") == 3
anchor = "        public static abstract class Credential implements Serializable {\n"
assert v3.count(anchor) == 1
v3 = v3.replace(anchor, anchor + '''            protected static String plainText(Secret secret) {
                return secret == null ? null : secret.getPlainText();
            }

''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import hudson.util.Secret;
import java.io.Serializable;

public final class TokenCredential implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String userName;
    private final Secret token; // stored encrypted by Jenkins

    public TokenCredential(String userName, String token) {
        this.userName = userName;
        this.token = Secret.fromString(token);
    }

    /**
     * Same "hold a credential and hand it out on demand" shape as the
     * Subversion credential classes, but the value is kept as a Secret, so the
     * persisted form is encrypted rather than reversibly encoded.
     */
    public String resolve() {
        return userName + ":" + Secret.toString(token);
    }
}
'''
assert "encrypted rather than reversibly encoded" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0195.")
