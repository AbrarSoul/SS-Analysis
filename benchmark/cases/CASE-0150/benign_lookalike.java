import io.jsonwebtoken.Jwts;
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
