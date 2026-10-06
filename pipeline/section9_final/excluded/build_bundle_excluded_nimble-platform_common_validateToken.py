"""
Section 9 ground-truth test bundle: CASE-0238
(nimble-platform/common, utility/src/main/java/eu/nimble/utility/validation/
ValidationUtil.java validateToken, CVE-2021-32631, CWE-290 authentication
bypass by spoofing).

Core vulnerable mechanism: `validateToken` is the authentication gate that turns
a bearer token into `Claims`. It checks the token against the Keycloak public key
with `Jwts.parser().setSigningKey(publicKey).parse(token)`. In jjwt 0.9.x
`parse` accepts ANY JWT, signed or not: a token whose header says
`"alg":"none"` (no signature part at all) is parsed and its body returned
without the key ever being used, so anyone can mint `{"sub":"admin", ...}`
claims. The upstream fix calls `parseJws(...)`, which only accepts a signed JWS
and verifies it with the key.

Measured caveat, kept in the manifest notes: `parseJws` alone leaves the algorithm
choice to the token header; the safe variant additionally requires the header
algorithm to be RS256 (the algorithm of the Keycloak realm key) before returning
the claims.

Sibling sites: `getClaims` in the same file decodes a token body with Base64 and
returns `Jwts.claims(map)` with no signature check at all, but it is a decoding
helper whose callers are expected to have called `validateToken` first, so it is
not changed by the upstream patch and not treated as a sibling of this bug here.

Verification: `validateToken` (and any helper it uses) is extracted verbatim from
each full file into a class compiled with javac against the REAL jjwt 0.9.1,
jose4j 0.6.5 (`RsaKeyUtil`) and jaxb-api jars, with only
`AuthenticationException` stubbed. A fresh RSA key pair is generated; tokens tried
are (a) a valid RS256 token, (b) an unsigned `alg:none` token claiming
`sub=admin`, and (c) an HS256 token whose secret is the public key's bytes.

Every variant is the FULL real file. `validateToken` is called by name through
IValidationUtil, so its name and signature are kept; the renamed variant renames
locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0238"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


BLOCK = '''    public Claims validateToken(String token) throws AuthenticationException {
        try {
            RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
            PublicKey publicKey = rsaKeyUtil.fromPemEncoded(keycloakPublicKey);

            return (Claims) Jwts.parser().setSigningKey(publicKey).parse(token.replace("Bearer ", "")).getBody();
        } catch (Exception e){
'''
assert original.count(BLOCK) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BLOCK, '''    public Claims validateToken(String token) throws AuthenticationException {
        try {
            RsaKeyUtil keyUtil = new RsaKeyUtil();
            PublicKey verificationKey = keyUtil.fromPemEncoded(keycloakPublicKey);

            return (Claims) Jwts.parser().setSigningKey(verificationKey).parse(token.replace("Bearer ", "")).getBody();
        } catch (Exception e){
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BLOCK, '''    private PublicKey loadKeycloakKey() throws Exception {
        return new RsaKeyUtil().fromPemEncoded(keycloakPublicKey);
    }

    public Claims validateToken(String token) throws AuthenticationException {
        try {
            PublicKey publicKey = loadKeycloakKey();
            String bare = token.replace("Bearer ", "");

            return (Claims) Jwts.parser().setSigningKey(publicKey).parse(bare).getBody();
        } catch (Exception e){
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, BLOCK, '''    public Claims validateToken(String token) throws AuthenticationException {
        try {
            RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
            PublicKey publicKey = rsaKeyUtil.fromPemEncoded(keycloakPublicKey);

            Jws<Claims> jws = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token.replace("Bearer ", ""));
            if (!"RS256".equals(jws.getHeader().getAlgorithm())) {
                throw new IllegalArgumentException("unexpected signature algorithm");
            }
            return jws.getBody();
        } catch (Exception e){
''')
v3 = swap(v3, "import io.jsonwebtoken.Claims;\n", "import io.jsonwebtoken.Claims;\nimport io.jsonwebtoken.Jws;\n")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

BENIGN = '''package eu.nimble.utility.validation;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * Standalone example of the same shape: read the display name out of a token
 * that was ALREADY verified by the authentication filter, only for logging. The
 * result is never used to authorise anything.
 */
public class TokenLogLabel {

    public static String labelFor(Claims verifiedClaims) {
        Object name = verifiedClaims == null ? null : verifiedClaims.get("name");
        return name == null ? "anonymous" : String.valueOf(name);
    }

    public static Claims emptyClaims() {
        return Jwts.claims();
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)
