package io.github.ak811.aes.aead;

import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-GCM backed by the Java Cryptography Architecture. The JDK's provider uses hardware AES and
 * carry-less multiplication instructions where available, so this is both fast and constant-time.
 * This is the default engine for the CLI.
 */
public final class JcaAesGcm implements Aead {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private final SecretKeySpec key;
    private final Cipher cipher;

    public JcaAesGcm(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes, got " + key.length);
        }
        this.key = new SecretKeySpec(key, "AES");
        try {
            this.cipher = Cipher.getInstance(TRANSFORMATION);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(TRANSFORMATION + " is not available in this Java runtime", e);
        }
    }

    @Override
    public byte[] encrypt(byte[] nonce, byte[] plaintext, int off, int len, byte[] aad) {
        Aead.checkNonce(nonce);
        Objects.checkFromIndexSize(off, len, plaintext.length);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * 8, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(plaintext, off, len);
        } catch (GeneralSecurityException e) {
            // The JDK refuses to encrypt twice with the same key and nonce; that surfaces here.
            throw new IllegalStateException("AES-GCM encryption failed: " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] decrypt(byte[] nonce, byte[] ciphertext, int off, int len, byte[] aad)
            throws AuthenticationException {
        Aead.checkNonce(nonce);
        Objects.checkFromIndexSize(off, len, ciphertext.length);
        if (len < TAG_LENGTH) {
            throw new AuthenticationException("ciphertext is shorter than the authentication tag");
        }
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH * 8, nonce));
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            return cipher.doFinal(ciphertext, off, len);
        } catch (AEADBadTagException e) {
            throw new AuthenticationException("authentication tag mismatch", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * No-op: {@link SecretKeySpec} keeps its own copy of the key and cannot be wiped. Callers should
     * still zeroize the array they passed to the constructor.
     */
    @Override
    public void close() {
        // Intentionally empty; see Javadoc.
    }
}
