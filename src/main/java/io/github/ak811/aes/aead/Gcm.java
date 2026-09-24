package io.github.ak811.aes.aead;

import io.github.ak811.aes.core.Aes;
import io.github.ak811.aes.core.BlockCipher;
import io.github.ak811.aes.mode.Ctr;
import io.github.ak811.aes.util.Bytes;
import java.util.Arrays;
import java.util.Objects;

/**
 * Galois/Counter Mode (NIST SP 800-38D) implemented from scratch on top of any 128-bit
 * {@link BlockCipher}.
 *
 * <p>Encryption is CTR mode starting at {@code inc32(J0)}; authentication is GHASH, a polynomial
 * MAC over GF(2^128) keyed with {@code H = E_K(0^128)}. The GF(2^128) multiplication below is
 * branch-free and uses no secret-indexed tables, so it runs in constant time. Only 96-bit nonces
 * and 128-bit tags are supported, which is what the standard recommends.
 *
 * <p>Output is byte-for-byte identical to the JDK's {@code AES/GCM/NoPadding}; the test suite
 * checks this on thousands of random inputs.
 */
public final class Gcm implements Aead {

    /** The reduction constant: x^128 + x^7 + x^2 + x + 1 in GCM's bit-reflected representation. */
    private static final long R = 0xE100000000000000L;

    private final BlockCipher cipher;
    private long hHi;
    private long hLo;
    private boolean closed;

    /** Takes ownership of {@code cipher}; closing this object closes it. */
    public Gcm(BlockCipher cipher) {
        this.cipher = Objects.requireNonNull(cipher, "cipher");
        byte[] h = new byte[BlockCipher.BLOCK_SIZE];
        cipher.encryptBlock(h, 0, h, 0);
        hHi = Bytes.getLongBE(h, 0);
        hLo = Bytes.getLongBE(h, 8);
        Bytes.zeroize(h);
    }

    /** AES-GCM using the from-scratch {@link Aes}. */
    public static Gcm withAes(byte[] key) {
        return new Gcm(new Aes(key));
    }

    @Override
    public byte[] encrypt(byte[] nonce, byte[] plaintext, int off, int len, byte[] aad) {
        ensureOpen();
        Aead.checkNonce(nonce);
        Objects.checkFromIndexSize(off, len, plaintext.length);

        byte[] j0 = j0(nonce);
        byte[] out = new byte[len + TAG_LENGTH];
        byte[] counter = j0.clone();
        Ctr.increment(counter, 4);
        Ctr.xorKeystream(cipher, counter, 4, plaintext, off, len, out, 0);
        computeTag(j0, aad, out, 0, len, out, len);
        return out;
    }

    @Override
    public byte[] decrypt(byte[] nonce, byte[] ciphertext, int off, int len, byte[] aad)
            throws AuthenticationException {
        ensureOpen();
        Aead.checkNonce(nonce);
        Objects.checkFromIndexSize(off, len, ciphertext.length);
        if (len < TAG_LENGTH) {
            throw new AuthenticationException("ciphertext is shorter than the authentication tag");
        }
        int ctLen = len - TAG_LENGTH;
        byte[] j0 = j0(nonce);

        // Verify before decrypting so no unauthenticated plaintext is ever produced.
        byte[] expected = new byte[TAG_LENGTH];
        computeTag(j0, aad, ciphertext, off, ctLen, expected, 0);
        byte[] actual = Arrays.copyOfRange(ciphertext, off + ctLen, off + len);
        if (!Bytes.constantTimeEquals(expected, actual)) {
            throw new AuthenticationException("authentication tag mismatch");
        }

        byte[] out = new byte[ctLen];
        byte[] counter = j0.clone();
        Ctr.increment(counter, 4);
        Ctr.xorKeystream(cipher, counter, 4, ciphertext, off, ctLen, out, 0);
        return out;
    }

    @Override
    public void close() {
        if (!closed) {
            cipher.close();
            hHi = 0;
            hLo = 0;
            closed = true;
        }
    }

    // ---------------------------------------------------------------- internals

    /** Pre-counter block for a 96-bit nonce: nonce || 0x00000001. */
    private static byte[] j0(byte[] nonce) {
        byte[] j0 = new byte[BlockCipher.BLOCK_SIZE];
        System.arraycopy(nonce, 0, j0, 0, NONCE_LENGTH);
        j0[15] = 1;
        return j0;
    }

    /** T = E_K(J0) XOR GHASH_H(A || pad || C || pad || len(A) || len(C)). */
    private void computeTag(byte[] j0, byte[] aad, byte[] c, int cOff, int cLen, byte[] tagOut, int tagOff) {
        byte[] a = aad == null ? new byte[0] : aad;
        long[] y = new long[2];
        ghashUpdate(y, a, 0, a.length);
        ghashUpdate(y, c, cOff, cLen);
        ghashBlock(y, (long) a.length * 8, (long) cLen * 8);

        byte[] mask = new byte[BlockCipher.BLOCK_SIZE];
        cipher.encryptBlock(j0, 0, mask, 0);
        byte[] s = new byte[BlockCipher.BLOCK_SIZE];
        Bytes.putLongBE(y[0], s, 0);
        Bytes.putLongBE(y[1], s, 8);
        for (int i = 0; i < TAG_LENGTH; i++) {
            tagOut[tagOff + i] = (byte) (mask[i] ^ s[i]);
        }
        Bytes.zeroize(mask, s);
    }

    /** Absorbs data in 16-byte blocks, zero-padding the final partial block. */
    private void ghashUpdate(long[] y, byte[] data, int off, int len) {
        int full = len & ~15;
        for (int i = 0; i < full; i += 16) {
            ghashBlock(y, Bytes.getLongBE(data, off + i), Bytes.getLongBE(data, off + i + 8));
        }
        if (full < len) {
            byte[] last = new byte[16];
            System.arraycopy(data, off + full, last, 0, len - full);
            ghashBlock(y, Bytes.getLongBE(last, 0), Bytes.getLongBE(last, 8));
        }
    }

    /**
     * Y = (Y XOR X) * H in GF(2^128), SP 800-38D Algorithm 1. Bits are processed MSB-first and
     * every step is expressed with masks instead of branches, so timing is independent of the data.
     */
    private void ghashBlock(long[] y, long xHi, long xLo) {
        long aHi = y[0] ^ xHi;
        long aLo = y[1] ^ xLo;
        long zHi = 0;
        long zLo = 0;
        long vHi = hHi;
        long vLo = hLo;
        for (int i = 0; i < 128; i++) {
            long bit = i < 64 ? (aHi >>> (63 - i)) & 1L : (aLo >>> (127 - i)) & 1L;
            long take = -bit;
            zHi ^= vHi & take;
            zLo ^= vLo & take;
            long reduce = -(vLo & 1L);
            vLo = (vLo >>> 1) | (vHi << 63);
            vHi = (vHi >>> 1) ^ (R & reduce);
        }
        y[0] = zHi;
        y[1] = zLo;
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("AEAD has been closed");
        }
    }
}
