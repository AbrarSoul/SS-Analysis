"""
Section 9 ground-truth test bundle: CASE-0121
(apache/ws-wss4j, EncryptedKeyProcessor.getRandomKey, CVE-2015-0226,
CWE-327 use of a broken/risky cryptographic construction -- a
Bleichenbacher-style PKCS#1 v1.5 oracle).

Core vulnerable mechanism: when RSA decryption of the EncryptedKey fails,
`getRandomKey()` is the countermeasure that makes the failure look like
success by substituting a RANDOM key. But it (1) starts with
`int size = 128` (BYTES; then `kgen.init(size * 8)` = 1024 bits), so for an
EncryptedKey with no data references AES key generation ALWAYS throws, and
(2) derives the algorithm and size from the attacker-controlled
EncryptedData, so an unknown or unsupported algorithm URI also makes it
throw. Every failure is turned into a WSSecurityException, so an attacker
can tell "decryption failed" from "decryption succeeded" and mount an
adaptive chosen-ciphertext (Bleichenbacher) attack on the RSA key. The
upstream fix sets `size = 16` and catches Throwable, falling back to a
plain AES-128 random key so the substitution can never fail visibly.

Every variant is the FULL real file with getRandomKey replaced. It is
private static with one in-file call site, which the renamed variant also
renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0121"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    private static byte[] getRandomKey(List<String> dataRefURIs, Document doc, WSDocInfo wsDocInfo) throws WSSecurityException {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CALL = "decryptedBytes = getRandomKey(dataRefURIs, elem.getOwnerDocument(), wsDocInfo);"
assert original.count(HDR) == 1 and original.count(CALL) == 1 and original.count("getRandomKey(") == 2
assert BLOCK.count("int size = 128;") == 1


def build(new_block, extra_after=None, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + (extra_after or "") + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


def rename_outside_comments_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        st = line.lstrip()
        if st.startswith("//") or st.startswith("*") or st.startswith("/*"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("getRandomKey(", "generateSubstituteKey(")
b = rename_outside_comments_strings(b, (("dataRefURIs", "refUris"), ("doc", "document"), ("wsDocInfo", "docInfo"),
                                        ("alg", "jceAlgorithm"), ("size", "keyBytes"), ("uri", "reference"),
                                        ("ee", "encData"), ("algorithmURI", "encAlgorithmUri"), ("kgen", "generator"),
                                        ("k", "generated"), ("ex", "failure")))
assert "int keyBytes = 128;" in b and "generator.init(keyBytes * 8);" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(
    build(b, new_call="decryptedBytes = generateSubstituteKey(dataRefURIs, elem.getOwnerDocument(), wsDocInfo);"))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace('''            KeyGenerator kgen = KeyGenerator.getInstance(alg);
            kgen.init(size * 8);
            SecretKey k = kgen.generateKey();
            return k.getEncoded();
''', '''            return newRandomKey(alg, size);
''')
helper = '''
    private static byte[] newRandomKey(String alg, int sizeInBytes) throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance(alg);
        kgen.init(sizeInBytes * 8);
        SecretKey k = kgen.generateKey();
        return k.getEncoded();
    }
'''
assert b != BLOCK and "int size = 128;" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Never lets a failure escape: the EncryptedData-derived algorithm/size are
# only ever OPTIONAL refinements of a correct AES-128 default (16 bytes),
# and any failure falls back to plain AES-128 (upstream: size=16 + a
# catch-Throwable fallback around the whole body).
b = '''    private static byte[] getRandomKey(List<String> dataRefURIs, Document doc, WSDocInfo wsDocInfo) throws WSSecurityException {
        String alg = "AES";
        int size = 16;
        if (!dataRefURIs.isEmpty()) {
            try {
                String uri = dataRefURIs.iterator().next();
                Element ee = ReferenceListProcessor.findEncryptedDataElement(doc, wsDocInfo, uri);
                String algorithmURI = X509Util.getEncAlgo(ee);
                String candidateAlg = JCEMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
                int candidateSize = WSSecurityUtil.getKeyLength(algorithmURI);
                KeyGenerator probe = KeyGenerator.getInstance(candidateAlg);
                probe.init(candidateSize * 8);
                alg = candidateAlg;
                size = candidateSize;
            } catch (Throwable t) {
                alg = "AES";
                size = 16;
            }
        }
        try {
            KeyGenerator kgen = KeyGenerator.getInstance(alg);
            kgen.init(size * 8);
            return kgen.generateKey().getEncoded();
        } catch (Throwable t) {
            try {
                KeyGenerator fallback = KeyGenerator.getInstance("AES");
                fallback.init(128);
                return fallback.generateKey().getEncoded();
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, null, e);
            }
        }
    }
'''
safe_source = build(b)
assert "int size = 128;" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SessionKeys {

    private static final String ALGORITHM = "AES";
    private static final int KEY_BYTES = 32;

    private SessionKeys() {}

    /**
     * Same KeyGenerator.getInstance(alg) / init(size * 8) / generateKey()
     * sequence, but the algorithm and size are developer-written constants
     * (and the size really is in bytes: 32 * 8 = 256 bits), so no input can
     * make it fail and there is no attacker-influenced choice to observe.
     */
    public static byte[] newSessionKey() throws Exception {
        KeyGenerator kgen = KeyGenerator.getInstance(ALGORITHM);
        kgen.init(KEY_BYTES * 8);
        SecretKey k = kgen.generateKey();
        return k.getEncoded();
    }
}
'''
assert "KEY_BYTES * 8" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0121.")
