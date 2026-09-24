package io.github.ak811.aes.mode;

import io.github.ak811.aes.core.BlockCipher;
import io.github.ak811.aes.util.Bytes;
import java.util.Objects;

/**
 * Counter mode (NIST SP 800-38A section 6.5): turns a block cipher into a stream cipher by encrypting
 * successive counter blocks and XOR-ing the result into the data. Encryption and decryption are the
 * same operation.
 *
 * <p>CTR provides confidentiality only. A counter block must never repeat under the same key, and
 * the ciphertext is malleable, so use {@link io.github.ak811.aes.aead.Gcm} unless you add your own
 * authentication.
 */
public final class Ctr {

    private Ctr() {
    }

    /** CTR over the full 128-bit block, treated as a big-endian counter. */
    public static byte[] apply(BlockCipher cipher, byte[] initialCounter, byte[] input) {
        byte[] out = new byte[input.length];
        xorKeystream(cipher, initialCounter, BlockCipher.BLOCK_SIZE, input, 0, input.length, out, 0);
        return out;
    }

    /**
     * XORs the keystream E(ctr), E(ctr + 1), ... into {@code in}, writing to {@code out}
     * (in-place is allowed with equal offsets). Only the last {@code counterBytes} bytes of the
     * block are incremented, wrapping within that field; GCM uses 4 ("inc32").
     */
    public static void xorKeystream(BlockCipher cipher, byte[] initialCounter, int counterBytes,
                                    byte[] in, int inOff, int len, byte[] out, int outOff) {
        Objects.requireNonNull(cipher, "cipher");
        if (initialCounter.length != BlockCipher.BLOCK_SIZE) {
            throw new IllegalArgumentException("counter block must be 16 bytes");
        }
        if (counterBytes < 1 || counterBytes > BlockCipher.BLOCK_SIZE) {
            throw new IllegalArgumentException("counterBytes must be in [1, 16]");
        }
        Objects.checkFromIndexSize(inOff, len, in.length);
        Objects.checkFromIndexSize(outOff, len, out.length);

        byte[] counter = initialCounter.clone();
        byte[] keystream = new byte[BlockCipher.BLOCK_SIZE];
        for (int done = 0; done < len; done += BlockCipher.BLOCK_SIZE) {
            cipher.encryptBlock(counter, 0, keystream, 0);
            int n = Math.min(BlockCipher.BLOCK_SIZE, len - done);
            for (int i = 0; i < n; i++) {
                out[outOff + done + i] = (byte) (in[inOff + done + i] ^ keystream[i]);
            }
            increment(counter, counterBytes);
        }
        Bytes.zeroize(counter, keystream);
    }

    /** Increments the big-endian integer formed by the last {@code counterBytes} bytes of the block. */
    public static void increment(byte[] block, int counterBytes) {
        for (int i = block.length - 1; i >= block.length - counterBytes; i--) {
            if (++block[i] != 0) {
                return;
            }
        }
    }
}
