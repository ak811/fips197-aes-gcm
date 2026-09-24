package io.github.ak811.aes.format;

import io.github.ak811.aes.io.AtomicFileOutput;
import io.github.ak811.aes.util.Bytes;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

/** Key files hold one Base64-encoded 256-bit key on a single line. */
public final class KeyFiles {

    private KeyFiles() {
    }

    /** Generates a new random key and writes it atomically (owner-only permissions on POSIX). */
    public static void generate(Path path, boolean overwrite, SecureRandom random) throws IOException {
        byte[] key = new byte[KeySource.RAW_KEY_LENGTH];
        byte[] encoded = null;
        try {
            random.nextBytes(key);
            encoded = (Base64.getEncoder().encodeToString(key) + "\n").getBytes(StandardCharsets.US_ASCII);
            try (AtomicFileOutput out = AtomicFileOutput.create(path, overwrite)) {
                out.stream().write(encoded);
                out.commit();
            }
        } finally {
            Bytes.zeroize(key, encoded);
        }
    }

    /** Reads a key file and returns the raw key bytes. The caller should zeroize the result. */
    public static byte[] read(Path path) throws IOException {
        byte[] raw = Files.readAllBytes(path);
        try {
            String text = new String(raw, StandardCharsets.US_ASCII).strip();
            byte[] key;
            try {
                key = Base64.getDecoder().decode(text);
            } catch (IllegalArgumentException e) {
                throw new FormatException("key file " + path + " is not valid Base64");
            }
            if (key.length != KeySource.RAW_KEY_LENGTH) {
                int found = key.length;
                Bytes.zeroize(key);
                throw new FormatException("key file " + path + " must contain a "
                        + KeySource.RAW_KEY_LENGTH + "-byte key, found " + found + " bytes");
            }
            return key;
        } finally {
            Bytes.zeroize(raw);
        }
    }
}
