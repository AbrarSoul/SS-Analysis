import hudson.util.Secret;

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
