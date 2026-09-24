package io.github.ak811.aes.core;

/**
 * A 128-bit block cipher primitive.
 *
 * <p>Implementations must support in-place operation ({@code in == out} with equal offsets).
 */
public interface BlockCipher extends AutoCloseable {

    /** Block size in bytes. */
    int BLOCK_SIZE = 16;

    void encryptBlock(byte[] in, int inOff, byte[] out, int outOff);

    void decryptBlock(byte[] in, int inOff, byte[] out, int outOff);

    /** Wipes the key schedule. The cipher must not be used afterwards. */
    @Override
    void close();
}
