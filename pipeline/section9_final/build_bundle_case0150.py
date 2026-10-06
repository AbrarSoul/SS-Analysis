"""
Section 9 ground-truth test bundle: CASE-0150
(dromara/sureness, core/src/main/java/com/usthe/sureness/util/JsonWebTokenUtil.java
issueJwtAll, CVE-2023-31581, CWE-798 use of hard-coded credentials).

Core vulnerable mechanism: the class signs and verifies JWTs with a HMAC key
that defaults to `DEFAULT_SECRET_KEY`, a constant published in the source.
`issueJwtAll` (the single funnel for every `issueJwt(...)` overload) happily
issues tokens signed with it, and `parseJwt` accepts anything signed with it,
so an application that never calls `setDefaultSecretKey` accepts tokens
anybody can forge. The upstream fix adds an `isUsedDefault` flag, cleared by
setDefaultSecretKey, and makes issueJwtAll throw while it is still set.

Measured caveat, kept in the manifest notes: upstream guards only ISSUING.
`parseJwt` still verifies against the default key, so a forged token signed
with the published key is still accepted after the upstream patch. The safe
variant therefore guards BOTH issueJwtAll and parseJwt (the sibling site), and
the vulnerable variants leave both.

Every variant is the FULL real file. issueJwtAll is public, called by all
issueJwt overloads in this file, so the renamed variant renames the method and
its four in-file call sites.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0150"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = '''    public static String issueJwtAll(String id, String subject, String issuer, Long period,
                                     String audience, String payload, Long notBefore,
                                     Map<String, Object> headerMap, Map<String, Object> customClaimMap){
'''
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert original.count(HDR) == 1
IFS = '''        if (id != null) {
            jwtBuilder.setId(id);
        }
        if (subject != null) {
            jwtBuilder.setSubject(subject);
        }
        if (issuer != null) {
            jwtBuilder.setIssuer(issuer);
        }
'''
PARSE = '''            MalformedJwtException, SignatureException, IllegalArgumentException {

        return Jwts.parserBuilder().setSigningKey(secretKey).build()
'''
assert BLOCK.count(IFS) == 1 and original.count(PARSE) == 1
assert original.count("issueJwtAll(") == 5


def build(new_block, extra_after=None, text=None):
    text = text or original
    assert new_block != BLOCK
    return text[:s] + new_block + (extra_after or "") + text[e:]


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("issueJwtAll", "issueFullJwt"), ("id", "tokenId"), ("subject", "userId"), ("issuer", "issuerName"),
                   ("period", "lifetime"), ("audience", "aud"), ("payload", "body"), ("notBefore", "validFrom"),
                   ("headerMap", "headers"), ("customClaimMap", "claims"), ("currentTimeMillis", "nowMs"),
                   ("jwtBuilder", "builder")))
assert "issueFullJwt(String tokenId, String userId, String issuerName, Long lifetime," in b
assert "claims.forEach(builder::claim)" in b and "builder.signWith(secretKey)" in b
v1 = build(b)
head, tail = v1[:s], v1[s:]
assert head.count("issueJwtAll(") == 4
v1 = head.replace("issueJwtAll(", "issueFullJwt(") + tail
assert "issueJwtAll" not in v1 and v1.count("issueFullJwt(") == 5
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(IFS, "        applyIdentity(jwtBuilder, id, subject, issuer);\n")
helper = '''
    private static void applyIdentity(JwtBuilder builder, String id, String subject, String issuer) {
        if (id != null) {
            builder.setId(id);
        }
        if (subject != null) {
            builder.setSubject(subject);
        }
        if (issuer != null) {
            builder.setIssuer(issuer);
        }
    }
'''
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# The published default key is detected by comparing the ACTIVE key's bytes
# with the default (so it also refuses when setDefaultSecretKey was called
# with the published value); upstream uses an isUsedDefault flag cleared by
# setDefaultSecretKey. Both issuing (issueJwtAll) and verifying (parseJwt)
# refuse the default key.
b = BLOCK.replace("        long currentTimeMillis = System.currentTimeMillis();\n",
                  "        requireCustomSecret();\n        long currentTimeMillis = System.currentTimeMillis();\n")
helper = '''
    private static void requireCustomSecret() {
        byte[] defaultKey = DatatypeConverter.parseBase64Binary(DEFAULT_SECRET_KEY);
        if (Arrays.equals(secretKey.getEncoded(), defaultKey)) {
            throw new IllegalStateException("Please config your custom jwt secret: JsonWebTokenUtil.setDefaultSecretKey");
        }
    }
'''
v3 = build(b, extra_after=helper)
v3 = v3.replace(PARSE, PARSE.replace("{\n\n        return", "{\n        requireCustomSecret();\n\n        return"))
assert v3.count("requireCustomSecret();") == 2 and "requireCustomSecret() {" in v3
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

public class ConfiguredJwtIssuer {

    private final Key key;

    /**
     * There is no built-in default: the HMAC secret must be supplied by the
     * deployer (at least 32 bytes) or construction fails, so no token can be
     * signed with a key that is published in the source.
     */
    public ConfiguredJwtIssuer(String secret) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("A jwt secret of at least 32 bytes must be configured");
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String issue(String subject, long periodSeconds) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(subject)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + periodSeconds * 1000))
                .signWith(key)
                .compact();
    }
}
'''
assert "at least 32 bytes" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0150.")
