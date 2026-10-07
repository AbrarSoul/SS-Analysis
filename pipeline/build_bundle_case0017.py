"""
Section 9 ground-truth test bundle: CASE-0017
(apache/spark, CVE-2024-23945, CWE-209 -- info exposure via error message).

Core vulnerable mechanism: when signature verification fails,
verifyAndExtract() throws an IllegalArgumentException whose message embeds
BOTH the expected (originalSignature, the secret HMAC the server computed
independently) and the attacker-supplied (currentSignature) values. An
attacker can use this as an oracle to read back the correct signature and
forge valid signed cookies. The real fix uses a generic "Invalid sign"
message with neither value.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0017"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = (
    "  public String verifyAndExtract(String signedStr) {\n"
    "    int index = signedStr.lastIndexOf(SIGNATURE);\n"
    "    if (index == -1) {\n"
    "      throw new IllegalArgumentException(\"Invalid input sign: \" + signedStr);\n"
    "    }\n"
    "    String originalSignature = signedStr.substring(index + SIGNATURE.length());\n"
    "    String rawValue = signedStr.substring(0, index);\n"
    "    String currentSignature = getSignature(rawValue);\n"
    "\n"
    "    if (LOG.isDebugEnabled()) {\n"
    "      LOG.debug(\"Signature generated for \" + rawValue + \" inside verify is \" + currentSignature);\n"
    "    }\n"
    "    if (!MessageDigest.isEqual(originalSignature.getBytes(), currentSignature.getBytes())) {\n"
    "      throw new IllegalArgumentException(\"Invalid sign, original = \" + originalSignature +\n"
    "        \" current = \" + currentSignature);\n"
    "    }\n"
    "    return rawValue;\n"
    "  }\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename originalSignature -> expectedSignature, currentSignature ->
# computedSignature throughout the method. Same exact vulnerability: both
# the expected and computed signature values are still embedded in the
# thrown exception's message.
RENAMED_BLOCK = (
    "  public String verifyAndExtract(String signedStr) {\n"
    "    int index = signedStr.lastIndexOf(SIGNATURE);\n"
    "    if (index == -1) {\n"
    "      throw new IllegalArgumentException(\"Invalid input sign: \" + signedStr);\n"
    "    }\n"
    "    String expectedSignature = signedStr.substring(index + SIGNATURE.length());\n"
    "    String rawValue = signedStr.substring(0, index);\n"
    "    String computedSignature = getSignature(rawValue);\n"
    "\n"
    "    if (LOG.isDebugEnabled()) {\n"
    "      LOG.debug(\"Signature generated for \" + rawValue + \" inside verify is \" + computedSignature);\n"
    "    }\n"
    "    if (!MessageDigest.isEqual(expectedSignature.getBytes(), computedSignature.getBytes())) {\n"
    "      throw new IllegalArgumentException(\"Invalid sign, original = \" + expectedSignature +\n"
    "        \" current = \" + computedSignature);\n"
    "    }\n"
    "    return rawValue;\n"
    "  }\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
assert renamed_source != original
assert "expectedSignature" in renamed_source and "computedSignature" in renamed_source
assert "originalSignature" not in renamed_source
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable / equivalent API-call
# formatting -- the message is built via String.format() and captured in
# a local before being thrown. Same exact vulnerability (both signature
# values still leaked), no renaming.
STRUCTURAL_BLOCK = VULNERABLE_BLOCK.replace(
    "    if (!MessageDigest.isEqual(originalSignature.getBytes(), currentSignature.getBytes())) {\n"
    "      throw new IllegalArgumentException(\"Invalid sign, original = \" + originalSignature +\n"
    "        \" current = \" + currentSignature);\n"
    "    }\n",
    "    if (!MessageDigest.isEqual(originalSignature.getBytes(), currentSignature.getBytes())) {\n"
    "      String errorMessage = String.format(\"Invalid sign, original = %s current = %s\",\n"
    "        originalSignature, currentSignature);\n"
    "      throw new IllegalArgumentException(errorMessage);\n"
    "    }\n",
)
assert STRUCTURAL_BLOCK != VULNERABLE_BLOCK
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "String.format(\"Invalid sign, original = %s current = %s\"," in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (neither signature value is ever
# exposed) but a differently-worded generic message than the real patch's
# literal "Invalid sign" string, so this sample isn't byte-identical to
# the known fix.
SAFE_BLOCK = VULNERABLE_BLOCK.replace(
    "    if (!MessageDigest.isEqual(originalSignature.getBytes(), currentSignature.getBytes())) {\n"
    "      throw new IllegalArgumentException(\"Invalid sign, original = \" + originalSignature +\n"
    "        \" current = \" + currentSignature);\n"
    "    }\n",
    "    if (!MessageDigest.isEqual(originalSignature.getBytes(), currentSignature.getBytes())) {\n"
    "      throw new IllegalArgumentException(\"Signature verification failed\");\n"
    "    }\n",
)
assert SAFE_BLOCK != VULNERABLE_BLOCK
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "Signature verification failed" in safe_source
assert "original = \" + originalSignature" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a method that also throws
# an IllegalArgumentException embedding a "signature"-related variable in
# its message, the same superficial shape as the vulnerable line, but the
# embedded value is a non-secret configuration name (the algorithm
# identifier), not an actual cryptographic signature -- genuinely safe to
# expose.
BENIGN_ADDITION = (
    "\n"
    "  private void validateSignatureAlgorithm(String algorithmName) {\n"
    "    // algorithmName is a non-secret configuration value (e.g.\n"
    "    // \"HmacSHA256\"), not an actual cryptographic signature, so\n"
    "    // including it in this message carries no information-exposure\n"
    "    // risk, unlike originalSignature/currentSignature above.\n"
    "    if (!\"HmacSHA256\".equals(algorithmName)) {\n"
    "      throw new IllegalArgumentException(\"Unsupported signature algorithm = \" + algorithmName);\n"
    "    }\n"
    "  }\n"
)
anchor = "  public String verifyAndExtract(String signedStr) {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "validateSignatureAlgorithm" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0017.")
