package io.github.ak811.aes.kdf;

import java.security.GeneralSecurityException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * PBKDF2-HMAC-SHA256 (RFC 8018) for turning a password into a key. The iteration count makes each
 * guess expensive; 600,000 is OWASP's current recommendation for this hash.
 */
public final class Pbkdf2 {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    private Pbkdf2() {
    }

    public static byte[] deriveKey(char[] password, byte[] salt, int iterations, int keyLengthBytes) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("password must not be empty");
        }
        if (iterations < 1) {
            throw new IllegalArgumentException("iterations must be positive");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLengthBytes * 8);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(ALGORITHM + " is not available in this Java runtime", e);
        } finally {
            spec.clearPassword();
        }
    }
}
