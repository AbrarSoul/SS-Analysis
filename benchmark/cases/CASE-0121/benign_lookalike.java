import javax.crypto.KeyGenerator;
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
