"""
Section 9 ground-truth test bundle: CASE-0103
(apache/cxf, DefaultSTSTokenCacher, CVE-2017-5656, CWE-384 session fixation
via cache-key collision).

Core vulnerable mechanism: `getIdFromToken()` derives the STS token-cache
key from whatever `wsu:Id` / `ID` / `AssertionID` attribute the (untrusted,
delegation) token itself declares. Two DIFFERENT tokens can declare the
SAME id, so an attacker's crafted token collides with a victim's cache
entry and `retrieveToken`/`storeToken` hand back (or overwrite) the
victim's associated issued token. The upstream fix derives the id from the
token's unique content (SAML assertion id by type, UsernameToken username,
SHA-256 of a BinarySecurityToken value).

Every variant is the FULL real file with getIdFromToken replaced. It has
two in-file call sites (retrieveToken, storeToken), which the renamed
variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0103"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    private static String getIdFromToken(Element token) {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CALL = "getIdFromToken(delegationToken)"
assert original.count(HDR) == 1 and original.count(CALL) == 2 and original.count("getIdFromToken(") == 3


def build(new_block, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if new_call:
        assert out.count(CALL) == 2
        out = out.replace(CALL, new_call)
    return out


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("getIdFromToken(", "cacheKeyFor(")
out = []
for line in b.split("\n"):
    if not line.lstrip().startswith("//"):
        line = re.sub(r"\btoken\b", "credential", line)
    out.append(line)
b = "\n".join(out)
assert "cacheKeyFor(Element credential)" in b and "credential.hasAttributeNS(WSConstants.WSU_NS" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b, "cacheKeyFor(delegationToken)"))

# --- Variant 2: structurally changed vulnerable variant ---
b = '''    private static String getIdFromToken(Element token) {
        if (token == null) {
            return "";
        }
        // Try to find the "Id" on the token.
        if (token.hasAttributeNS(WSConstants.WSU_NS, "Id")) {
            return token.getAttributeNS(WSConstants.WSU_NS, "Id");
        }
        if (token.hasAttributeNS(null, "ID")) {
            return token.getAttributeNS(null, "ID");
        }
        if (token.hasAttributeNS(null, "AssertionID")) {
            return token.getAttributeNS(null, "AssertionID");
        }
        return "";
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Key = Base64(SHA-256(serialized token XML)): unique to the token's actual
# content, so a token that merely DECLARES someone else's Id no longer
# collides (upstream selects a type-specific unique field instead).
b = '''    // Cache key derived from the token's full content, never from an attacker-declared id
    private static String getIdFromToken(Element token) {
        if (token == null) {
            return "";
        }
        try {
            org.w3c.dom.ls.DOMImplementationLS ls = (org.w3c.dom.ls.DOMImplementationLS)
                token.getOwnerDocument().getImplementation().getFeature("LS", "3.0");
            String xml = ls.createLSSerializer().writeToString(token);
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.Base64.getEncoder().encodeToString(digest);
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
'''
safe_source = build(b)
assert 'getAttributeNS(null, "ID")' not in safe_source.split("getIdFromToken(Element token)")[1].split("\n    }\n")[0]
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import org.apache.wss4j.dom.WSConstants;
import org.w3c.dom.Element;

public final class TokenDebugLabel {

    private TokenDebugLabel() {}

    /**
     * Same wsu:Id / ID / AssertionID attribute chain, but the value is only
     * embedded in a human-readable debug label. It is never used as a cache
     * key or any other security identity, so a token that declares someone
     * else's Id gains nothing.
     */
    public static String labelFor(Element token) {
        if (token == null) {
            return "token[none]";
        }
        String declared = "unnamed";
        if (token.hasAttributeNS(WSConstants.WSU_NS, "Id")) {
            declared = token.getAttributeNS(WSConstants.WSU_NS, "Id");
        } else if (token.hasAttributeNS(null, "ID")) {
            declared = token.getAttributeNS(null, "ID");
        } else if (token.hasAttributeNS(null, "AssertionID")) {
            declared = token.getAttributeNS(null, "AssertionID");
        }
        return "token[" + declared + "]";
    }
}
'''
assert "cache" not in benign_source.split("*/")[1]
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0103.")
