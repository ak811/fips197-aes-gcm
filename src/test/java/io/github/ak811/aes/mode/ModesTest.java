package io.github.ak811.aes.mode;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.ak811.aes.core.Aes;
import io.github.ak811.aes.selftest.TestVectors;
import java.util.HexFormat;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class ModesTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void ecbMatchesSp80038a() {
        TestVectors.Block v = TestVectors.ECB_AES128;
        try (Aes aes = new Aes(HEX.parseHex(v.key()))) {
            byte[] ct = Ecb.encrypt(aes, HEX.parseHex(v.plaintext()));
            assertArrayEquals(HEX.parseHex(v.ciphertext()), ct);
            assertArrayEquals(HEX.parseHex(v.plaintext()), Ecb.decrypt(aes, ct));
        }
    }

    @Test
    void ecbRejectsPartialBlocks() {
        try (Aes aes = new Aes(new byte[16])) {
            assertThrows(IllegalArgumentException.class, () -> Ecb.encrypt(aes, new byte[17]));
        }
    }

    @Test
    void ctrMatchesSp80038a() {
        TestVectors.Stream v = TestVectors.CTR_AES128;
        try (Aes aes = new Aes(HEX.parseHex(v.key()))) {
            byte[] ct = Ctr.apply(aes, HEX.parseHex(v.iv()), HEX.parseHex(v.plaintext()));
            assertArrayEquals(HEX.parseHex(v.ciphertext()), ct);
            assertArrayEquals(HEX.parseHex(v.plaintext()), Ctr.apply(aes, HEX.parseHex(v.iv()), ct));
        }
    }

    @Test
    void ctrMatchesJdkForArbitraryLengths() throws Exception {
        Random random = new Random(7);
        Cipher jdk = Cipher.getInstance("AES/CTR/NoPadding");
        for (int length = 0; length < 200; length++) {
            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            byte[] data = new byte[length];
            random.nextBytes(key);
            random.nextBytes(iv);
            random.nextBytes(data);
            jdk.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            try (Aes aes = new Aes(key)) {
                assertArrayEquals(jdk.doFinal(data), Ctr.apply(aes, iv, data), "length " + length);
            }
        }
    }

    @Test
    void ctrCounterCarriesAcrossBytes() throws Exception {
        byte[] key = new byte[16];
        byte[] iv = HEX.parseHex("00000000000000000000fffffffffffe");
        byte[] data = new byte[64];
        Cipher jdk = Cipher.getInstance("AES/CTR/NoPadding");
        jdk.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        try (Aes aes = new Aes(key)) {
            assertArrayEquals(jdk.doFinal(data), Ctr.apply(aes, iv, data));
        }
    }

    @Test
    void incrementWrapsWithinCounterField() {
        byte[] block = HEX.parseHex("000000000000000000000000ffffffff");
        Ctr.increment(block, 4);
        assertArrayEquals(HEX.parseHex("00000000000000000000000000000000"), block);

        block = HEX.parseHex("000000000000000000000000ffffffff");
        Ctr.increment(block, 16);
        assertArrayEquals(HEX.parseHex("00000000000000000000000100000000"), block);
    }
}
