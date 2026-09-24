package io.github.ak811.aes.kdf;

import io.github.ak811.aes.util.Bytes;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HKDF with HMAC-SHA256 (RFC 5869). Used to derive a unique per-file key from a key file. */
public final class Hkdf {

    private static final String HMAC = "HmacSHA256";
    private static final int HASH_LENGTH = 32;

    private Hkdf() {
    }

    /**
     * @param ikm    input keying material (must already be high-entropy; use PBKDF2 for passwords)
     * @param salt   optional salt; {@code null} or empty means HashLen zero bytes, per the RFC
     * @param info   optional context string binding the output to its purpose
     * @param length output length in bytes, at most 255 * 32
     */
    public static byte[] deriveSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (length < 1 || length > 255 * HASH_LENGTH) {
            throw new IllegalArgumentException("HKDF output length must be in [1, " + 255 * HASH_LENGTH + "]");
        }
        byte[] prk = null;
        byte[] t = new byte[0];
        try {
            Mac mac = Mac.getInstance(HMAC);
            byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[HASH_LENGTH] : salt;
            mac.init(new SecretKeySpec(effectiveSalt, HMAC));
            prk = mac.doFinal(ikm);

            mac.init(new SecretKeySpec(prk, HMAC));
            byte[] out = new byte[length];
            int pos = 0;
            for (int counter = 1; pos < length; counter++) {
                mac.update(t);
                if (info != null) {
                    mac.update(info);
                }
                mac.update((byte) counter);
                Bytes.zeroize(t);
                t = mac.doFinal();
                int n = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, out, pos, n);
                pos += n;
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(HMAC + " is not available in this Java runtime", e);
        } finally {
            Bytes.zeroize(prk, t);
        }
    }
}
