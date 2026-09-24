package io.github.ak811.aes.kdf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.ak811.aes.selftest.TestVectors;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class KdfTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void hkdfMatchesRfc5869() {
        for (TestVectors.Kdf v : TestVectors.HKDF) {
            byte[] okm = Hkdf.deriveSha256(HEX.parseHex(v.ikm()), HEX.parseHex(v.salt()), HEX.parseHex(v.info()), v.length());
            assertArrayEquals(HEX.parseHex(v.okm()), okm, v.name());
        }
    }

    @Test
    void hkdfRejectsInvalidLengths() {
        assertThrows(IllegalArgumentException.class, () -> Hkdf.deriveSha256(new byte[32], null, null, 0));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.deriveSha256(new byte[32], null, null, 255 * 32 + 1));
    }

    @Test
    void pbkdf2IsDeterministicAndSaltSensitive() {
        char[] password = "correct horse battery staple".toCharArray();
        byte[] salt = new byte[16];
        byte[] a = Pbkdf2.deriveKey(password, salt, 1000, 32);
        byte[] b = Pbkdf2.deriveKey(password, salt, 1000, 32);
        salt[0] = 1;
        byte[] c = Pbkdf2.deriveKey(password, salt, 1000, 32);
        assertEquals(32, a.length);
        assertArrayEquals(a, b);
        assertFalse(Arrays.equals(a, c));
    }

    @Test
    void pbkdf2MatchesRfc7914Vector() {
        // RFC 7914 section 11: PBKDF2-HMAC-SHA256, P="passwd", S="salt", c=1, dkLen=64
        byte[] dk = Pbkdf2.deriveKey("passwd".toCharArray(), "salt".getBytes(), 1, 64);
        assertArrayEquals(HEX.parseHex(
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                        + "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"), dk);
    }

    @Test
    void pbkdf2RejectsEmptyPassword() {
        assertThrows(IllegalArgumentException.class, () -> Pbkdf2.deriveKey(new char[0], new byte[16], 1000, 32));
    }
}
