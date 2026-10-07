import com.fit2cloud.common.utils.MD5Util;

import java.security.SecureRandom;

public class TemporaryPasswords {

    private static final String ALPHABET =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*";
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Same "user.setPassword(MD5Util.md5(<new password>))" shape, but the new
     * password is NOT chosen by the requester: it is a fresh 16-character
     * value drawn from a SecureRandom over a 64-symbol alphabet (96 bits of
     * entropy), so no weak or reused password can be introduced here.
     */
    public String resetToTemporaryPassword(com.fit2cloud.base.entity.User user) {
        StringBuilder generated = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            generated.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        user.setPassword(MD5Util.md5(generated.toString()));
        return generated.toString();
    }
}
