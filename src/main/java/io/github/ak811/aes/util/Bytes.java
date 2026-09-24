package io.github.ak811.aes.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;

/** Small byte-level helpers shared across the project. */
public final class Bytes {

    private Bytes() {
    }

    /** Compares two arrays in time that depends only on their lengths, never on their contents. */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Best-effort wipe of sensitive material. The JVM may still hold copies elsewhere
     * (garbage-collector moves, JIT registers), so this reduces exposure rather than eliminating it.
     */
    public static void zeroize(byte[]... arrays) {
        for (byte[] a : arrays) {
            if (a != null) {
                Arrays.fill(a, (byte) 0);
            }
        }
    }

    /** Best-effort wipe of a password buffer. */
    public static void zeroize(char[] chars) {
        if (chars != null) {
            Arrays.fill(chars, '\0');
        }
    }

    public static int getIntBE(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16)
                | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    public static void putIntBE(int v, byte[] b, int off) {
        b[off] = (byte) (v >>> 24);
        b[off + 1] = (byte) (v >>> 16);
        b[off + 2] = (byte) (v >>> 8);
        b[off + 3] = (byte) v;
    }

    public static long getLongBE(byte[] b, int off) {
        return ((long) getIntBE(b, off) << 32) | (getIntBE(b, off + 4) & 0xFFFFFFFFL);
    }

    public static void putLongBE(long v, byte[] b, int off) {
        putIntBE((int) (v >>> 32), b, off);
        putIntBE((int) v, b, off + 4);
    }

    /**
     * Reads until {@code len} bytes have been read or the stream ends.
     *
     * @return the number of bytes actually read (less than {@code len} only at end of stream)
     */
    public static int readFully(InputStream in, byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int r = in.read(buf, off + total, len - total);
            if (r < 0) {
                break;
            }
            total += r;
        }
        return total;
    }
}
