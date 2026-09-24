package io.github.ak811.aes.aead;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.ak811.aes.selftest.TestVectors;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import org.junit.jupiter.api.Test;

class GcmTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void bothEnginesMatchPublishedVectors() throws Exception {
        for (Engine engine : Engine.values()) {
            for (TestVectors.Aead v : TestVectors.GCM) {
                byte[] expected = HEX.parseHex(v.ciphertext() + v.tag());
                try (Aead aead = engine.aesGcm(HEX.parseHex(v.key()))) {
                    byte[] sealed = aead.encrypt(HEX.parseHex(v.nonce()), HEX.parseHex(v.plaintext()), HEX.parseHex(v.aad()));
                    assertArrayEquals(expected, sealed, engine + " " + v.name());
                    byte[] opened = aead.decrypt(HEX.parseHex(v.nonce()), expected, HEX.parseHex(v.aad()));
                    assertArrayEquals(HEX.parseHex(v.plaintext()), opened, engine + " " + v.name());
                }
            }
        }
    }

    /** Differential test: the from-scratch GCM must agree with the JDK on every input. */
    @Test
    void referenceMatchesJdkOnRandomInputs() throws Exception {
        Random random = new Random(1234);
        for (int i = 0; i < 1500; i++) {
            byte[] key = new byte[new int[] {16, 24, 32}[i % 3]];
            byte[] nonce = new byte[12];
            byte[] aad = new byte[random.nextInt(70)];
            byte[] plaintext = new byte[i < 300 ? i : random.nextInt(5000)];
            random.nextBytes(key);
            random.nextBytes(nonce);
            random.nextBytes(aad);
            random.nextBytes(plaintext);

            try (Aead jca = Engine.JCA.aesGcm(key); Aead reference = Engine.REFERENCE.aesGcm(key)) {
                byte[] a = jca.encrypt(nonce, plaintext, aad);
                byte[] b = reference.encrypt(nonce, plaintext, aad);
                assertArrayEquals(a, b, "iteration " + i);
                assertArrayEquals(plaintext, reference.decrypt(nonce, a, aad));
                assertArrayEquals(plaintext, jca.decrypt(nonce, b, aad));
            }
        }
    }

    @Test
    void anySingleBitFlipIsRejected() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] aad = "header".getBytes();
        byte[] plaintext = "attack at dawn, bring snacks".getBytes();
        for (Engine engine : Engine.values()) {
            try (Aead aead = engine.aesGcm(key)) {
                byte[] sealed = aead.encrypt(nonce, plaintext, aad);
                for (int bit = 0; bit < sealed.length * 8; bit++) {
                    byte[] tampered = sealed.clone();
                    tampered[bit / 8] ^= (byte) (1 << (bit % 8));
                    assertThrows(AuthenticationException.class, () -> aead.decrypt(nonce, tampered, aad),
                            engine + " bit " + bit);
                }
            }
        }
    }

    @Test
    void wrongAadNonceOrKeyIsRejected() throws Exception {
        byte[] key = new byte[16];
        byte[] nonce = new byte[12];
        byte[] aad = {1, 2, 3};
        for (Engine engine : Engine.values()) {
            byte[] sealed;
            try (Aead aead = engine.aesGcm(key)) {
                sealed = aead.encrypt(nonce, new byte[40], aad);
                assertThrows(AuthenticationException.class, () -> aead.decrypt(nonce, sealed, new byte[] {1, 2, 4}));
                assertThrows(AuthenticationException.class, () -> aead.decrypt(nonce, sealed, null));
                byte[] otherNonce = nonce.clone();
                otherNonce[11] = 1;
                assertThrows(AuthenticationException.class, () -> aead.decrypt(otherNonce, sealed, aad));
            }
            byte[] otherKey = key.clone();
            otherKey[0] = 1;
            try (Aead aead = engine.aesGcm(otherKey)) {
                assertThrows(AuthenticationException.class, () -> aead.decrypt(nonce, sealed, aad));
            }
        }
    }

    @Test
    void truncatedCiphertextIsRejected() throws Exception {
        for (Engine engine : Engine.values()) {
            try (Aead aead = engine.aesGcm(new byte[16])) {
                byte[] sealed = aead.encrypt(new byte[12], new byte[33], null);
                for (int len = 0; len < sealed.length; len++) {
                    byte[] cut = Arrays.copyOf(sealed, len);
                    assertThrows(AuthenticationException.class, () -> aead.decrypt(new byte[12], cut, null));
                }
            }
        }
    }

    @Test
    void outputLengthIsPlaintextPlusTag() {
        try (Aead aead = Engine.REFERENCE.aesGcm(new byte[32])) {
            assertEquals(Aead.TAG_LENGTH, aead.encrypt(new byte[12], new byte[0], null).length);
            assertEquals(100 + Aead.TAG_LENGTH, aead.encrypt(new byte[12], new byte[100], null).length);
        }
    }

    @Test
    void rejectsNonStandardNonceLengths() {
        for (Engine engine : Engine.values()) {
            try (Aead aead = engine.aesGcm(new byte[16])) {
                assertThrows(IllegalArgumentException.class, () -> aead.encrypt(new byte[8], new byte[1], null));
                assertThrows(IllegalArgumentException.class, () -> aead.encrypt(new byte[16], new byte[1], null));
            }
        }
    }

    @Test
    void honoursOffsetAndLength() throws Exception {
        byte[] buffer = new byte[100];
        new Random(3).nextBytes(buffer);
        byte[] slice = Arrays.copyOfRange(buffer, 10, 60);
        for (Engine engine : Engine.values()) {
            try (Aead aead = engine.aesGcm(new byte[16])) {
                byte[] nonce = new byte[12];
                nonce[0] = (byte) engine.ordinal();
                byte[] fromSlice = aead.encrypt(nonce, buffer, 10, 50, null);
                assertArrayEquals(slice, aead.decrypt(nonce, fromSlice, null));

                byte[] padded = new byte[fromSlice.length + 9];
                System.arraycopy(fromSlice, 0, padded, 4, fromSlice.length);
                assertArrayEquals(slice, aead.decrypt(nonce, padded, 4, fromSlice.length, null));
            }
        }
    }
}
