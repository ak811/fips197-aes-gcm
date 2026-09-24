package io.github.ak811.aes.format;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.ak811.aes.aead.Aead;
import io.github.ak811.aes.aead.AuthenticationException;
import io.github.ak811.aes.aead.Engine;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

class FileCryptoTest {

    private static final int SEGMENT = 4096;
    private static final int CT_SEGMENT = SEGMENT + Aead.TAG_LENGTH;

    private static byte[] randomBytes(int length, long seed) {
        byte[] b = new byte[length];
        new Random(seed).nextBytes(b);
        return b;
    }

    private static KeySource rawKey() {
        return KeySource.rawKey(randomBytes(KeySource.RAW_KEY_LENGTH, 99));
    }

    private static EncryptOptions options(Engine engine) {
        return EncryptOptions.defaults()
                .withEngine(engine)
                .withSegmentSize(SEGMENT)
                .withIterations(EncryptOptions.MIN_ITERATIONS);
    }

    private static byte[] encrypt(byte[] plaintext, KeySource key, EncryptOptions options) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FileCrypto.encrypt(new ByteArrayInputStream(plaintext), out, key, options);
        return out.toByteArray();
    }

    private static byte[] decrypt(byte[] ciphertext, KeySource key, Engine engine)
            throws IOException, AuthenticationException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        FileCrypto.decrypt(new ByteArrayInputStream(ciphertext), out, key, engine);
        return out.toByteArray();
    }

    @Test
    void roundTripsAroundSegmentBoundaries() throws Exception {
        int[] sizes = {0, 1, 15, 16, 17, SEGMENT - 1, SEGMENT, SEGMENT + 1, 2 * SEGMENT, 3 * SEGMENT + 5, 50_000};
        for (Engine engine : Engine.values()) {
            try (KeySource key = rawKey()) {
                for (int size : sizes) {
                    byte[] plaintext = randomBytes(size, size);
                    byte[] ciphertext = encrypt(plaintext, key, options(engine));
                    assertEquals(FileCrypto.ciphertextLength(size, SEGMENT), ciphertext.length, "size " + size);
                    assertArrayEquals(plaintext, decrypt(ciphertext, key, engine), engine + " size " + size);
                }
            }
        }
    }

    @Test
    void enginesAreInteroperable() throws Exception {
        byte[] plaintext = randomBytes(3 * SEGMENT + 123, 5);
        try (KeySource key = rawKey()) {
            byte[] fromJca = encrypt(plaintext, key, options(Engine.JCA));
            byte[] fromReference = encrypt(plaintext, key, options(Engine.REFERENCE));
            assertArrayEquals(plaintext, decrypt(fromJca, key, Engine.REFERENCE));
            assertArrayEquals(plaintext, decrypt(fromReference, key, Engine.JCA));
        }
    }

    @Test
    void passwordRoundTripAndWrongPassword() throws Exception {
        byte[] plaintext = "meet me at the usual place".getBytes();
        byte[] ciphertext;
        try (KeySource password = KeySource.password("correct horse battery staple".toCharArray())) {
            ciphertext = encrypt(plaintext, password, options(Engine.JCA));
            assertArrayEquals(plaintext, decrypt(ciphertext, password, Engine.JCA));
        }
        try (KeySource wrong = KeySource.password("correct horse battery stapler".toCharArray())) {
            assertThrows(AuthenticationException.class, () -> decrypt(ciphertext, wrong, Engine.JCA));
        }
    }

    @Test
    void encryptionIsRandomized() throws Exception {
        byte[] plaintext = new byte[1000];
        try (KeySource key = rawKey()) {
            byte[] a = encrypt(plaintext, key, options(Engine.JCA));
            byte[] b = encrypt(plaintext, key, options(Engine.JCA));
            assertFalse(Arrays.equals(a, b), "same plaintext must not give the same ciphertext");
        }
    }

    @Test
    void detectsModificationAnywhereAfterTheSignature() throws Exception {
        byte[] plaintext = randomBytes(2 * SEGMENT + 300, 11);
        try (KeySource key = rawKey()) {
            byte[] ciphertext = encrypt(plaintext, key, options(Engine.JCA));
            int[] positions = {
                10,                                      // salt
                30,                                      // nonce prefix
                FileHeader.LENGTH,                       // first byte of segment 0
                FileHeader.LENGTH + CT_SEGMENT - 1,      // tag of segment 0
                FileHeader.LENGTH + CT_SEGMENT + 100,    // segment 1
                ciphertext.length - 1                    // tag of the final segment
            };
            for (int pos : positions) {
                byte[] tampered = ciphertext.clone();
                tampered[pos] ^= 0x01;
                assertThrows(AuthenticationException.class, () -> decrypt(tampered, key, Engine.JCA), "position " + pos);
            }
        }
    }

    @Test
    void detectsTruncationAtSegmentBoundary() throws Exception {
        byte[] plaintext = randomBytes(3 * SEGMENT + 100, 12);
        try (KeySource key = rawKey()) {
            byte[] ciphertext = encrypt(plaintext, key, options(Engine.JCA));
            // Dropping the final segment leaves a well-formed file whose last segment was not sealed as last.
            byte[] dropLast = Arrays.copyOf(ciphertext, FileHeader.LENGTH + 3 * CT_SEGMENT);
            assertThrows(AuthenticationException.class, () -> decrypt(dropLast, key, Engine.JCA));

            byte[] headerOnly = Arrays.copyOf(ciphertext, FileHeader.LENGTH);
            assertThrows(AuthenticationException.class, () -> decrypt(headerOnly, key, Engine.JCA));

            byte[] oneByteShort = Arrays.copyOf(ciphertext, ciphertext.length - 1);
            assertThrows(AuthenticationException.class, () -> decrypt(oneByteShort, key, Engine.JCA));
        }
    }

    @Test
    void detectsAppendedData() throws Exception {
        try (KeySource key = rawKey()) {
            byte[] ciphertext = encrypt(randomBytes(SEGMENT, 13), key, options(Engine.JCA));
            byte[] extended = Arrays.copyOf(ciphertext, ciphertext.length + 40);
            assertThrows(AuthenticationException.class, () -> decrypt(extended, key, Engine.JCA));
        }
    }

    @Test
    void detectsReorderedSegments() throws Exception {
        try (KeySource key = rawKey()) {
            byte[] ciphertext = encrypt(randomBytes(3 * SEGMENT, 14), key, options(Engine.JCA));
            byte[] swapped = ciphertext.clone();
            int first = FileHeader.LENGTH;
            int second = FileHeader.LENGTH + CT_SEGMENT;
            System.arraycopy(ciphertext, second, swapped, first, CT_SEGMENT);
            System.arraycopy(ciphertext, first, swapped, second, CT_SEGMENT);
            assertThrows(AuthenticationException.class, () -> decrypt(swapped, key, Engine.JCA));
        }
    }

    @Test
    void detectsSegmentsSplicedFromAnotherFile() throws Exception {
        byte[] plaintext = randomBytes(2 * SEGMENT, 15);
        try (KeySource key = rawKey()) {
            byte[] a = encrypt(plaintext, key, options(Engine.JCA));
            byte[] b = encrypt(plaintext, key, options(Engine.JCA));
            byte[] spliced = a.clone();
            System.arraycopy(b, FileHeader.LENGTH, spliced, FileHeader.LENGTH, CT_SEGMENT);
            assertThrows(AuthenticationException.class, () -> decrypt(spliced, key, Engine.JCA));
        }
    }

    @Test
    void rejectsKeyTypeMismatch() throws Exception {
        byte[] ciphertext;
        try (KeySource password = KeySource.password("hunter2hunter2".toCharArray())) {
            ciphertext = encrypt(new byte[10], password, options(Engine.JCA));
        }
        try (KeySource key = rawKey()) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> decrypt(ciphertext, key, Engine.JCA));
            assertEquals("this file is protected with a password, not a key file", e.getMessage());
        }
    }

    @Test
    void rejectsInvalidOptions() {
        assertThrows(IllegalArgumentException.class, () -> EncryptOptions.defaults().withIterations(1000));
        assertThrows(IllegalArgumentException.class, () -> EncryptOptions.defaults().withSegmentSize(100));
        assertThrows(IllegalArgumentException.class, () -> KeySource.rawKey(new byte[16]));
        assertThrows(IllegalArgumentException.class, () -> KeySource.password(new char[0]));
    }
}
