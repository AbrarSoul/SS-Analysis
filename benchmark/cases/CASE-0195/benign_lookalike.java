import hudson.util.Secret;
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
