package io.github.ak811.aes.aead;

/**
 * Authenticated encryption with associated data.
 *
 * <p>Ciphertexts are {@code encrypted data || 16-byte tag}. Decryption either returns the exact
 * plaintext or throws {@link AuthenticationException}; it never returns unauthenticated data.
 *
 * <p>A nonce must never be reused with the same key. Reuse with GCM reveals the XOR of the two
 * plaintexts and lets an attacker forge messages.
 */
public interface Aead extends AutoCloseable {

    /** Nonce length in bytes (96 bits, the size GCM is designed around). */
    int NONCE_LENGTH = 12;

    /** Authentication tag length in bytes. */
    int TAG_LENGTH = 16;

    byte[] encrypt(byte[] nonce, byte[] plaintext, int off, int len, byte[] aad);

    byte[] decrypt(byte[] nonce, byte[] ciphertext, int off, int len, byte[] aad)
            throws AuthenticationException;

    default byte[] encrypt(byte[] nonce, byte[] plaintext, byte[] aad) {
        return encrypt(nonce, plaintext, 0, plaintext.length, aad);
    }

    default byte[] decrypt(byte[] nonce, byte[] ciphertext, byte[] aad) throws AuthenticationException {
        return decrypt(nonce, ciphertext, 0, ciphertext.length, aad);
    }

    /** Releases key material where the implementation can. */
    @Override
    void close();

    static void checkNonce(byte[] nonce) {
        if (nonce == null || nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("nonce must be exactly " + NONCE_LENGTH + " bytes");
        }
    }
}
