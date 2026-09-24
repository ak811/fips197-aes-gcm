package io.github.ak811.aes.format;

import io.github.ak811.aes.aead.Aead;
import io.github.ak811.aes.aead.AuthenticationException;
import io.github.ak811.aes.aead.Engine;
import io.github.ak811.aes.kdf.Hkdf;
import io.github.ak811.aes.kdf.Pbkdf2;
import io.github.ak811.aes.util.Bytes;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Streaming, authenticated file encryption with AES-256-GCM.
 *
 * <p>Layout: {@code header || segment_0 || ... || segment_n}. The plaintext is split into
 * fixed-size segments (default 64 KiB) and each one is sealed with AES-GCM under a per-file key, a
 * nonce derived from its position (see {@link FileHeader#segmentNonce}), and the header as
 * associated data. This gives:
 *
 * <ul>
 *   <li>constant memory use for files of any size (no need to buffer the whole file);</li>
 *   <li>detection of any modification, truncation, extension or reordering of segments;</li>
 *   <li>a fresh random salt per file, so every file gets a unique key and nonces never collide
 *       across files.</li>
 * </ul>
 *
 * <p>The construction follows the "online AE" / STREAM design used by Google Tink's streaming AEAD
 * and by {@code age}.
 *
 * <p><b>Decrypting callers must discard all output if an exception is thrown</b>, because the
 * segments before the failing one have already been written. The CLI does this by writing to a
 * temporary file and renaming it only on success.
 */
public final class FileCrypto {

    public static final String FILE_EXTENSION = ".aesf";

    private static final byte[] HKDF_INFO = "aesf v1 file key".getBytes(StandardCharsets.US_ASCII);
    private static final int FILE_KEY_LENGTH = 32;

    private FileCrypto() {
    }

    public static void encrypt(InputStream in, OutputStream out, KeySource key, EncryptOptions options)
            throws IOException {
        byte[] salt = new byte[FileHeader.SALT_LENGTH];
        byte[] prefix = new byte[FileHeader.NONCE_PREFIX_LENGTH];
        options.random().nextBytes(salt);
        options.random().nextBytes(prefix);
        KdfType kdf = key.kdfType();
        int iterations = kdf == KdfType.PBKDF2_HMAC_SHA256 ? options.iterations() : 0;
        FileHeader header = new FileHeader(kdf, iterations, salt, options.segmentSize(), prefix);
        byte[] aad = header.encode();

        int segmentSize = header.segmentSize();
        byte[] buf = new byte[segmentSize + 1];
        byte[] fileKey = deriveFileKey(header, key);
        try (Aead aead = options.engine().aesGcm(fileKey)) {
            out.write(aad);
            // Read one byte past the segment so we know whether the current segment is the last.
            int n = Bytes.readFully(in, buf, 0, segmentSize + 1);
            for (long index = 0; ; index++) {
                boolean last = n <= segmentSize;
                int len = last ? n : segmentSize;
                out.write(aead.encrypt(header.segmentNonce(index, last), buf, 0, len, aad));
                if (last) {
                    break;
                }
                buf[0] = buf[segmentSize];
                n = 1 + Bytes.readFully(in, buf, 1, segmentSize);
            }
            out.flush();
        } finally {
            Bytes.zeroize(fileKey, buf);
        }
    }

    public static void decrypt(InputStream in, OutputStream out, KeySource key, Engine engine)
            throws IOException, AuthenticationException {
        FileHeader header = FileHeader.read(in);
        byte[] aad = header.encode();

        int ctSegment = header.segmentSize() + Aead.TAG_LENGTH;
        byte[] buf = new byte[ctSegment + 1];
        byte[] fileKey = deriveFileKey(header, key);
        try (Aead aead = engine.aesGcm(fileKey)) {
            int n = Bytes.readFully(in, buf, 0, ctSegment + 1);
            for (long index = 0; ; index++) {
                boolean last = n <= ctSegment;
                int len = last ? n : ctSegment;
                byte[] plaintext = aead.decrypt(header.segmentNonce(index, last), buf, 0, len, aad);
                out.write(plaintext);
                Bytes.zeroize(plaintext);
                if (last) {
                    break;
                }
                buf[0] = buf[ctSegment];
                n = 1 + Bytes.readFully(in, buf, 1, ctSegment);
            }
            out.flush();
        } finally {
            Bytes.zeroize(fileKey);
        }
    }

    /** Size of the encrypted output for a plaintext of {@code plaintextLength} bytes. */
    public static long ciphertextLength(long plaintextLength, int segmentSize) {
        long segments = plaintextLength == 0 ? 1 : (plaintextLength + segmentSize - 1) / segmentSize;
        return FileHeader.LENGTH + plaintextLength + segments * Aead.TAG_LENGTH;
    }

    private static byte[] deriveFileKey(FileHeader header, KeySource key) {
        if (key.kdfType() != header.kdf()) {
            throw new IllegalArgumentException(header.kdf() == KdfType.PBKDF2_HMAC_SHA256
                    ? "this file is protected with a password, not a key file"
                    : "this file is protected with a key file, not a password");
        }
        if (key instanceof KeySource.Password password) {
            return Pbkdf2.deriveKey(password.chars(), header.salt(), header.iterations(), FILE_KEY_LENGTH);
        }
        KeySource.RawKey raw = (KeySource.RawKey) key;
        return Hkdf.deriveSha256(raw.bytes(), header.salt(), HKDF_INFO, FILE_KEY_LENGTH);
    }
}
