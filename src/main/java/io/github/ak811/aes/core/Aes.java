package io.github.ak811.aes.core;

import java.util.Arrays;
import java.util.Objects;

/**
 * The AES block cipher (FIPS-197) implemented from scratch, supporting 128-, 192- and 256-bit keys.
 *
 * <p>The S-box and the GF(2^8) multiplication tables are derived at class-load time from their
 * mathematical definitions rather than pasted in as constants, so the code documents where every
 * number comes from.
 *
 * <p><b>Side channels:</b> this implementation indexes lookup tables with secret-dependent values,
 * so its timing can leak key material through CPU caches to a co-located attacker. It is verified
 * byte-for-byte against the official test vectors and the JDK, but for production traffic prefer
 * the {@code JCA} engine, which uses hardware AES instructions (AES-NI / ARMv8 Crypto) that run in
 * constant time.
 */
public final class Aes implements BlockCipher {

    private static final int[] SBOX = new int[256];
    private static final int[] INV_SBOX = new int[256];
    private static final int[] MUL2 = new int[256];
    private static final int[] MUL3 = new int[256];
    private static final int[] MUL9 = new int[256];
    private static final int[] MUL11 = new int[256];
    private static final int[] MUL13 = new int[256];
    private static final int[] MUL14 = new int[256];

    static {
        for (int a = 0; a < 256; a++) {
            // S-box = affine transform of the multiplicative inverse in GF(2^8) (FIPS-197 section 5.1.1).
            int inv = a == 0 ? 0 : inverse(a);
            int s = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63;
            SBOX[a] = s;
            INV_SBOX[s] = a;
            MUL2[a] = gmul(a, 2);
            MUL3[a] = gmul(a, 3);
            MUL9[a] = gmul(a, 9);
            MUL11[a] = gmul(a, 11);
            MUL13[a] = gmul(a, 13);
            MUL14[a] = gmul(a, 14);
        }
    }

    private final int rounds;
    private final int[] roundKeys;
    private boolean closed;

    /**
     * @param key a 16-, 24- or 32-byte key (AES-128, AES-192, AES-256). The array is not retained.
     */
    public Aes(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24 or 32 bytes, got " + key.length);
        }
        int nk = key.length / 4;
        rounds = nk + 6;
        roundKeys = expandKey(key, nk, rounds);
    }

    /** Number of rounds: 10, 12 or 14. */
    public int rounds() {
        return rounds;
    }

    @Override
    public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        checkArgs(in, inOff, out, outOff);
        int[] s = load(in, inOff);
        addRoundKey(s, 0);
        for (int round = 1; round < rounds; round++) {
            substitute(s, SBOX);
            shiftRows(s);
            mixColumns(s);
            addRoundKey(s, round);
        }
        substitute(s, SBOX);
        shiftRows(s);
        addRoundKey(s, rounds);
        store(s, out, outOff);
    }

    @Override
    public void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        checkArgs(in, inOff, out, outOff);
        int[] s = load(in, inOff);
        addRoundKey(s, rounds);
        for (int round = rounds - 1; round >= 1; round--) {
            invShiftRows(s);
            substitute(s, INV_SBOX);
            addRoundKey(s, round);
            invMixColumns(s);
        }
        invShiftRows(s);
        substitute(s, INV_SBOX);
        addRoundKey(s, 0);
        store(s, out, outOff);
    }

    @Override
    public void close() {
        Arrays.fill(roundKeys, 0);
        closed = true;
    }

    // ---------------------------------------------------------------- key schedule (FIPS-197 section 5.2)

    private static int[] expandKey(byte[] key, int nk, int rounds) {
        int total = 4 * (rounds + 1);
        int[] w = new int[total];
        for (int i = 0; i < nk; i++) {
            w[i] = ((key[4 * i] & 0xFF) << 24) | ((key[4 * i + 1] & 0xFF) << 16)
                    | ((key[4 * i + 2] & 0xFF) << 8) | (key[4 * i + 3] & 0xFF);
        }
        int rcon = 0x01;
        for (int i = nk; i < total; i++) {
            int t = w[i - 1];
            if (i % nk == 0) {
                t = subWord(Integer.rotateLeft(t, 8)) ^ (rcon << 24);
                rcon = MUL2[rcon];
            } else if (nk > 6 && i % nk == 4) {
                t = subWord(t);
            }
            w[i] = w[i - nk] ^ t;
        }
        return w;
    }

    private static int subWord(int w) {
        return (SBOX[w >>> 24] << 24) | (SBOX[(w >>> 16) & 0xFF] << 16)
                | (SBOX[(w >>> 8) & 0xFF] << 8) | SBOX[w & 0xFF];
    }

    // ---------------------------------------------------------------- round transformations
    // State layout: s[row + 4 * column]; input bytes fill the state column by column.

    private void addRoundKey(int[] s, int round) {
        for (int c = 0; c < 4; c++) {
            int k = roundKeys[4 * round + c];
            s[4 * c] ^= k >>> 24;
            s[4 * c + 1] ^= (k >>> 16) & 0xFF;
            s[4 * c + 2] ^= (k >>> 8) & 0xFF;
            s[4 * c + 3] ^= k & 0xFF;
        }
    }

    private static void substitute(int[] s, int[] box) {
        for (int i = 0; i < 16; i++) {
            s[i] = box[s[i]];
        }
    }

    /** Row r is rotated left by r positions. */
    private static void shiftRows(int[] s) {
        int t = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t;

        t = s[2];
        s[2] = s[10];
        s[10] = t;
        t = s[6];
        s[6] = s[14];
        s[14] = t;

        t = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t;
    }

    /** Row r is rotated right by r positions. */
    private static void invShiftRows(int[] s) {
        int t = s[13];
        s[13] = s[9];
        s[9] = s[5];
        s[5] = s[1];
        s[1] = t;

        t = s[2];
        s[2] = s[10];
        s[10] = t;
        t = s[6];
        s[6] = s[14];
        s[14] = t;

        t = s[3];
        s[3] = s[7];
        s[7] = s[11];
        s[11] = s[15];
        s[15] = t;
    }

    private static void mixColumns(int[] s) {
        for (int c = 0; c < 16; c += 4) {
            int a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
            s[c] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3;
            s[c + 1] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3;
            s[c + 2] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3];
            s[c + 3] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3];
        }
    }

    private static void invMixColumns(int[] s) {
        for (int c = 0; c < 16; c += 4) {
            int a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
            s[c] = MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3];
            s[c + 1] = MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3];
            s[c + 2] = MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3];
            s[c + 3] = MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3];
        }
    }

    // ---------------------------------------------------------------- GF(2^8) arithmetic

    /** Multiplication in GF(2^8) modulo the AES polynomial x^8 + x^4 + x^3 + x + 1. */
    static int gmul(int a, int b) {
        int product = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                product ^= a;
            }
            boolean carry = (a & 0x80) != 0;
            a = (a << 1) & 0xFF;
            if (carry) {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        return product;
    }

    /** Multiplicative inverse by exhaustive search; runs once per value at class-load time. */
    private static int inverse(int a) {
        for (int b = 1; b < 256; b++) {
            if (gmul(a, b) == 1) {
                return b;
            }
        }
        throw new AssertionError("no inverse for " + a);
    }

    private static int rotl8(int x, int shift) {
        return ((x << shift) | (x >>> (8 - shift))) & 0xFF;
    }

    // ---------------------------------------------------------------- helpers

    private void checkArgs(byte[] in, int inOff, byte[] out, int outOff) {
        if (closed) {
            throw new IllegalStateException("cipher has been closed");
        }
        Objects.checkFromIndexSize(inOff, BLOCK_SIZE, in.length);
        Objects.checkFromIndexSize(outOff, BLOCK_SIZE, out.length);
    }

    private static int[] load(byte[] in, int off) {
        int[] s = new int[16];
        for (int i = 0; i < 16; i++) {
            s[i] = in[off + i] & 0xFF;
        }
        return s;
    }

    private static void store(int[] s, byte[] out, int off) {
        for (int i = 0; i < 16; i++) {
            out[off + i] = (byte) s[i];
            s[i] = 0;
        }
    }
}
