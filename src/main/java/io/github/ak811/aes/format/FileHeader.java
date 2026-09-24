package io.github.ak811.aes.format;

import io.github.ak811.aes.aead.Aead;
import io.github.ak811.aes.util.Bytes;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * The fixed 37-byte header at the start of every encrypted file (all integers big-endian):
 *
 * <pre>
 * offset size field
 *      0    4 magic "AESF"
 *      4    1 format version (1)
 *      5    1 key derivation: 1 = PBKDF2-HMAC-SHA256 (password), 2 = HKDF-SHA256 (key file)
 *      6    4 PBKDF2 iterations (0 for key files)
 *     10   16 random salt
 *     26    4 plaintext segment size in bytes
 *     30    7 random nonce prefix
 * </pre>
 *
 * <p>The whole header is passed as associated data to every segment, so any change to it makes
 * decryption fail.
 */
public final class FileHeader {

    public static final int VERSION = 1;
    public static final int SALT_LENGTH = 16;
    public static final int NONCE_PREFIX_LENGTH = 7;
    public static final int LENGTH = 4 + 1 + 1 + 4 + SALT_LENGTH + 4 + NONCE_PREFIX_LENGTH;

    public static final int MIN_SEGMENT_SIZE = 4 * 1024;
    public static final int MAX_SEGMENT_SIZE = 16 * 1024 * 1024;
    /** Upper bound accepted when reading, so a crafted header cannot stall the reader for hours. */
    public static final int MAX_ITERATIONS = 10_000_000;
    /** The segment index is a 32-bit unsigned counter inside the nonce. */
    public static final long MAX_SEGMENTS = 1L << 32;

    private static final byte[] MAGIC = {'A', 'E', 'S', 'F'};

    private final KdfType kdf;
    private final int iterations;
    private final byte[] salt;
    private final int segmentSize;
    private final byte[] noncePrefix;

    public FileHeader(KdfType kdf, int iterations, byte[] salt, int segmentSize, byte[] noncePrefix) {
        this.kdf = Objects.requireNonNull(kdf, "kdf");
        if (salt.length != SALT_LENGTH) {
            throw new IllegalArgumentException("salt must be " + SALT_LENGTH + " bytes");
        }
        if (noncePrefix.length != NONCE_PREFIX_LENGTH) {
            throw new IllegalArgumentException("nonce prefix must be " + NONCE_PREFIX_LENGTH + " bytes");
        }
        String problem = validate(kdf, iterations, segmentSize);
        if (problem != null) {
            throw new IllegalArgumentException(problem);
        }
        this.iterations = iterations;
        this.salt = salt.clone();
        this.segmentSize = segmentSize;
        this.noncePrefix = noncePrefix.clone();
    }

    /** Reads and validates a header from the start of {@code in}. */
    public static FileHeader read(InputStream in) throws IOException {
        byte[] raw = new byte[LENGTH];
        int n = Bytes.readFully(in, raw, 0, LENGTH);
        if (n < MAGIC.length || !Arrays.equals(raw, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
            throw new FormatException("not an encrypted file (missing AESF signature)");
        }
        if (n < LENGTH) {
            throw new FormatException("file is truncated: incomplete header");
        }
        return parse(raw);
    }

    /** Parses and validates an encoded header. */
    public static FileHeader parse(byte[] raw) throws FormatException {
        if (raw.length != LENGTH || !Arrays.equals(raw, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
            throw new FormatException("not an encrypted file (missing AESF signature)");
        }
        ByteBuffer b = ByteBuffer.wrap(raw, MAGIC.length, LENGTH - MAGIC.length);
        int version = b.get() & 0xFF;
        if (version != VERSION) {
            throw new FormatException("unsupported format version " + version + " (this build reads version " + VERSION + ")");
        }
        KdfType kdf = KdfType.fromId(b.get() & 0xFF);
        int iterations = b.getInt();
        byte[] salt = new byte[SALT_LENGTH];
        b.get(salt);
        int segmentSize = b.getInt();
        byte[] prefix = new byte[NONCE_PREFIX_LENGTH];
        b.get(prefix);

        String problem = validate(kdf, iterations, segmentSize);
        if (problem != null) {
            throw new FormatException("invalid header: " + problem);
        }
        return new FileHeader(kdf, iterations, salt, segmentSize, prefix);
    }

    private static String validate(KdfType kdf, int iterations, int segmentSize) {
        if (segmentSize < MIN_SEGMENT_SIZE || segmentSize > MAX_SEGMENT_SIZE) {
            return "segment size " + segmentSize + " outside [" + MIN_SEGMENT_SIZE + ", " + MAX_SEGMENT_SIZE + "]";
        }
        if (kdf == KdfType.PBKDF2_HMAC_SHA256 && (iterations < 1 || iterations > MAX_ITERATIONS)) {
            return "PBKDF2 iteration count " + Integer.toUnsignedString(iterations) + " outside [1, " + MAX_ITERATIONS + "]";
        }
        if (kdf == KdfType.HKDF_SHA256 && iterations != 0) {
            return "iteration count must be 0 for key-file encryption";
        }
        return null;
    }

    public byte[] encode() {
        return ByteBuffer.allocate(LENGTH)
                .put(MAGIC)
                .put((byte) VERSION)
                .put((byte) kdf.id())
                .putInt(iterations)
                .put(salt)
                .putInt(segmentSize)
                .put(noncePrefix)
                .array();
    }

    /**
     * The 96-bit nonce for a segment: {@code prefix (7) || index (4, big-endian) || last flag (1)}.
     * Binding the index prevents reordering; the flag makes truncation at a segment boundary
     * detectable, because the new final segment was not encrypted as final.
     */
    public byte[] segmentNonce(long index, boolean last) {
        if (index < 0 || index >= MAX_SEGMENTS) {
            throw new IllegalStateException("too many segments for one file");
        }
        byte[] nonce = new byte[Aead.NONCE_LENGTH];
        System.arraycopy(noncePrefix, 0, nonce, 0, NONCE_PREFIX_LENGTH);
        Bytes.putIntBE((int) index, nonce, NONCE_PREFIX_LENGTH);
        nonce[Aead.NONCE_LENGTH - 1] = (byte) (last ? 1 : 0);
        return nonce;
    }

    public KdfType kdf() {
        return kdf;
    }

    public int iterations() {
        return iterations;
    }

    public byte[] salt() {
        return salt.clone();
    }

    public int segmentSize() {
        return segmentSize;
    }

    public byte[] noncePrefix() {
        return noncePrefix.clone();
    }
}
