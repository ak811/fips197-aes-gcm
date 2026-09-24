package io.github.ak811.aes.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.ak811.aes.selftest.TestVectors;
import java.util.HexFormat;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class AesTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void matchesFips197Vectors() {
        for (TestVectors.Block v : TestVectors.AES) {
            try (Aes aes = new Aes(HEX.parseHex(v.key()))) {
                byte[] plaintext = HEX.parseHex(v.plaintext());
                byte[] ciphertext = new byte[16];
                aes.encryptBlock(plaintext, 0, ciphertext, 0);
                assertArrayEquals(HEX.parseHex(v.ciphertext()), ciphertext, v.name());

                byte[] decrypted = new byte[16];
                aes.decryptBlock(ciphertext, 0, decrypted, 0);
                assertArrayEquals(plaintext, decrypted, v.name());
            }
        }
    }

    @Test
    void matchesJdkOnRandomKeysAndBlocks() throws Exception {
        Random random = new Random(42);
        Cipher jdk = Cipher.getInstance("AES/ECB/NoPadding");
        for (int keyLength : new int[] {16, 24, 32}) {
            for (int i = 0; i < 500; i++) {
                byte[] key = new byte[keyLength];
                byte[] block = new byte[16];
                random.nextBytes(key);
                random.nextBytes(block);

                jdk.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
                byte[] expected = jdk.doFinal(block);

                try (Aes aes = new Aes(key)) {
                    byte[] actual = new byte[16];
                    aes.encryptBlock(block, 0, actual, 0);
                    assertArrayEquals(expected, actual, "AES-" + keyLength * 8 + " iteration " + i);

                    byte[] back = new byte[16];
                    aes.decryptBlock(actual, 0, back, 0);
                    assertArrayEquals(block, back);
                }
            }
        }
    }

    @Test
    void roundCountFollowsKeySize() {
        assertEquals(10, new Aes(new byte[16]).rounds());
        assertEquals(12, new Aes(new byte[24]).rounds());
        assertEquals(14, new Aes(new byte[32]).rounds());
    }

    @Test
    void supportsInPlaceOperationAtOffsets() {
        byte[] key = HEX.parseHex("000102030405060708090a0b0c0d0e0f");
        byte[] buffer = new byte[40];
        byte[] block = HEX.parseHex("00112233445566778899aabbccddeeff");
        System.arraycopy(block, 0, buffer, 7, 16);
        try (Aes aes = new Aes(key)) {
            aes.encryptBlock(buffer, 7, buffer, 7);
            byte[] ct = new byte[16];
            System.arraycopy(buffer, 7, ct, 0, 16);
            assertArrayEquals(HEX.parseHex("69c4e0d86a7b0430d8cdb78070b4c55a"), ct);
            aes.decryptBlock(buffer, 7, buffer, 7);
            System.arraycopy(buffer, 7, ct, 0, 16);
            assertArrayEquals(block, ct);
        }
    }

    @Test
    void rejectsInvalidKeyLengths() {
        for (int length : new int[] {0, 8, 15, 17, 20, 31, 33, 64}) {
            assertThrows(IllegalArgumentException.class, () -> new Aes(new byte[length]));
        }
    }

    @Test
    void cannotBeUsedAfterClose() {
        Aes aes = new Aes(new byte[16]);
        aes.close();
        assertThrows(IllegalStateException.class, () -> aes.encryptBlock(new byte[16], 0, new byte[16], 0));
    }

    @Test
    void rejectsShortBuffers() {
        try (Aes aes = new Aes(new byte[16])) {
            assertThrows(IndexOutOfBoundsException.class, () -> aes.encryptBlock(new byte[15], 0, new byte[16], 0));
            assertThrows(IndexOutOfBoundsException.class, () -> aes.encryptBlock(new byte[16], 1, new byte[16], 0));
        }
    }

    @Test
    void galoisMultiplicationMatchesFips197Examples() {
        // FIPS-197 section 4.2: {57} * {83} = {c1}, {57} * {13} = {fe}
        assertEquals(0xC1, Aes.gmul(0x57, 0x83));
        assertEquals(0xFE, Aes.gmul(0x57, 0x13));
    }
}
