package io.github.ak811.aes.format;

import io.github.ak811.aes.aead.Engine;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Tunable parameters for {@link FileCrypto#encrypt}. The defaults are the recommended settings;
 * decryption reads everything it needs from the file header.
 *
 * @param engine      AES-GCM implementation to use
 * @param iterations  PBKDF2 iterations for password-protected files (ignored for key files)
 * @param segmentSize plaintext bytes per authenticated segment
 * @param random      source of salts and nonces
 */
public record EncryptOptions(Engine engine, int iterations, int segmentSize, SecureRandom random) {

    public static final int DEFAULT_ITERATIONS = 600_000;
    public static final int MIN_ITERATIONS = 100_000;
    public static final int DEFAULT_SEGMENT_SIZE = 64 * 1024;

    public EncryptOptions {
        Objects.requireNonNull(engine, "engine");
        Objects.requireNonNull(random, "random");
        if (iterations < MIN_ITERATIONS || iterations > FileHeader.MAX_ITERATIONS) {
            throw new IllegalArgumentException("iterations must be in [" + MIN_ITERATIONS + ", " + FileHeader.MAX_ITERATIONS + "]");
        }
        if (segmentSize < FileHeader.MIN_SEGMENT_SIZE || segmentSize > FileHeader.MAX_SEGMENT_SIZE) {
            throw new IllegalArgumentException("segment size must be in [" + FileHeader.MIN_SEGMENT_SIZE + ", " + FileHeader.MAX_SEGMENT_SIZE + "] bytes");
        }
    }

    public static EncryptOptions defaults() {
        return new EncryptOptions(Engine.JCA, DEFAULT_ITERATIONS, DEFAULT_SEGMENT_SIZE, new SecureRandom());
    }

    public EncryptOptions withEngine(Engine value) {
        return new EncryptOptions(value, iterations, segmentSize, random);
    }

    public EncryptOptions withIterations(int value) {
        return new EncryptOptions(engine, value, segmentSize, random);
    }

    public EncryptOptions withSegmentSize(int value) {
        return new EncryptOptions(engine, iterations, value, random);
    }
}
