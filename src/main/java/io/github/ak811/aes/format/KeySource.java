package io.github.ak811.aes.format;

import io.github.ak811.aes.util.Bytes;
import java.util.Objects;

/**
 * The secret a file is protected with: either a password or a 256-bit key. Copies its input, so
 * callers should wipe their own buffers; {@link #close()} wipes the copy.
 */
public sealed interface KeySource extends AutoCloseable permits KeySource.Password, KeySource.RawKey {

    /** Length of a raw key in bytes (256 bits). */
    int RAW_KEY_LENGTH = 32;

    static Password password(char[] password) {
        return new Password(password);
    }

    static RawKey rawKey(byte[] key) {
        return new RawKey(key);
    }

    KdfType kdfType();

    @Override
    void close();

    /** A password, stretched with PBKDF2. */
    final class Password implements KeySource {
        private final char[] chars;

        private Password(char[] chars) {
            Objects.requireNonNull(chars, "password");
            if (chars.length == 0) {
                throw new IllegalArgumentException("password must not be empty");
            }
            this.chars = chars.clone();
        }

        char[] chars() {
            return chars;
        }

        @Override
        public KdfType kdfType() {
            return KdfType.PBKDF2_HMAC_SHA256;
        }

        @Override
        public void close() {
            Bytes.zeroize(chars);
        }
    }

    /** A uniformly random 256-bit key, expanded per file with HKDF. */
    final class RawKey implements KeySource {
        private final byte[] key;

        private RawKey(byte[] key) {
            Objects.requireNonNull(key, "key");
            if (key.length != RAW_KEY_LENGTH) {
                throw new IllegalArgumentException("raw key must be " + RAW_KEY_LENGTH + " bytes, got " + key.length);
            }
            this.key = key.clone();
        }

        byte[] bytes() {
            return key;
        }

        @Override
        public KdfType kdfType() {
            return KdfType.HKDF_SHA256;
        }

        @Override
        public void close() {
            Bytes.zeroize(key);
        }
    }
}
