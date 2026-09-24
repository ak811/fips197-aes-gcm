package io.github.ak811.aes.mode;

import io.github.ak811.aes.core.BlockCipher;

/**
 * Electronic Codebook mode: every block is encrypted independently with the same key.
 *
 * <p><b>Do not use ECB to protect data.</b> Identical plaintext blocks produce identical ciphertext
 * blocks, so structure leaks straight through (see the {@code ecb-demo} command). It exists here only
 * for the NIST SP 800-38A known-answer tests and for that demonstration.
 */
public final class Ecb {

    private Ecb() {
    }

    public static byte[] encrypt(BlockCipher cipher, byte[] data) {
        byte[] out = requireBlocks(data).clone();
        for (int i = 0; i < out.length; i += BlockCipher.BLOCK_SIZE) {
            cipher.encryptBlock(out, i, out, i);
        }
        return out;
    }

    public static byte[] decrypt(BlockCipher cipher, byte[] data) {
        byte[] out = requireBlocks(data).clone();
        for (int i = 0; i < out.length; i += BlockCipher.BLOCK_SIZE) {
            cipher.decryptBlock(out, i, out, i);
        }
        return out;
    }

    private static byte[] requireBlocks(byte[] data) {
        if (data.length % BlockCipher.BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("ECB input must be a multiple of 16 bytes (no padding is applied)");
        }
        return data;
    }
}
