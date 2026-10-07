"""
Section 9 ground-truth test bundle: CASE-0105
(apache/hive, LlapSignerImpl, CVE-2024-23953, CWE-208 observable timing
discrepancy).

Core vulnerable mechanism: `checkSignature()` verifies a message MAC with
`Arrays.equals(signature, expectedSignature)`, which returns at the FIRST
differing byte. The response time therefore reveals how long a prefix of
a forged signature is correct, so an attacker can recover a valid MAC byte
by byte. The upstream fix uses the constant-time `MessageDigest.isEqual`.

Every variant is the FULL real file with checkSignature's body replaced.
checkSignature is an @Override of LlapSigner and has no in-file callers, so
the renamed variant renames parameters/locals only (renaming the method
would break the interface contract).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0105"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "  public void checkSignature(byte[] message, byte[] signature, int keyId)\n"
s = original.index(HDR)
e = original.index("\n  }\n", s) + len("\n  }\n")
BLOCK = original[s:e]
CMP = "    if (Arrays.equals(signature, expectedSignature)) return;\n"
assert original.count(HDR) == 1 and BLOCK.count(CMP) == 1
assert original.count("checkSignature(") == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for old, new in pairs:
                parts[i] = re.sub(r"\b%s\b" % old, new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


b = rename_outside_strings(BLOCK, (("expectedSignature", "computedMac"), ("signature", "providedMac"),
                                   ("message", "payload"), ("keyId", "keyIndex")))
assert "Arrays.equals(providedMac, computedMac)" in b and '"Message signature does not match"' in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(CMP, '''    boolean matches = Arrays.equals(signature, expectedSignature);
    if (matches) {
      return;
    }
''')
assert b != BLOCK and "Arrays.equals" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Hand-rolled constant-time comparison (upstream uses MessageDigest.isEqual):
# always visits every byte of the expected MAC, ORs the differences, and only
# then decides; null-safe like Arrays.equals.
b = BLOCK.replace(CMP, '''    if (signature != null && expectedSignature != null) {
      int diff = signature.length ^ expectedSignature.length;
      for (int i = 0; i < expectedSignature.length; i++) {
        byte given = i < signature.length ? signature[i] : 0;
        diff |= given ^ expectedSignature[i];
      }
      if (diff == 0) {
        return;
      }
    }
''')
safe_source = build(b)
assert "Arrays.equals" not in safe_source and "MessageDigest" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.util.Arrays;

public class PublishedArtifactCheck {

    private PublishedArtifactCheck() {}

    /**
     * Same Arrays.equals(byte[], byte[]) comparison, but of two digests of a
     * PUBLIC artifact that anyone can download and hash. There is no secret
     * whose bytes the timing could reveal, so early-exit comparison is fine.
     */
    public static boolean matchesPublishedDigest(byte[] computedDigest, byte[] publishedDigest) {
        return Arrays.equals(computedDigest, publishedDigest);
    }
}
'''
assert "secret" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0105.")
