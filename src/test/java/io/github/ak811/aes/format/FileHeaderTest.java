package io.github.ak811.aes.format;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.ak811.aes.util.Bytes;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class FileHeaderTest {

    private static FileHeader sample() {
        byte[] salt = new byte[FileHeader.SALT_LENGTH];
        Arrays.fill(salt, (byte) 0x5A);
        byte[] prefix = {1, 2, 3, 4, 5, 6, 7};
        return new FileHeader(KdfType.PBKDF2_HMAC_SHA256, 600_000, salt, 65536, prefix);
    }

    @Test
    void encodesToFixedLayoutAndParsesBack() throws Exception {
        FileHeader header = sample();
        byte[] encoded = header.encode();
        assertEquals(37, encoded.length);
        assertArrayEquals(new byte[] {'A', 'E', 'S', 'F', 1, 1}, Arrays.copyOf(encoded, 6));
        assertEquals(600_000, Bytes.getIntBE(encoded, 6));

        FileHeader parsed = FileHeader.parse(encoded);
        assertEquals(header.kdf(), parsed.kdf());
        assertEquals(header.iterations(), parsed.iterations());
        assertEquals(header.segmentSize(), parsed.segmentSize());
        assertArrayEquals(header.salt(), parsed.salt());
        assertArrayEquals(header.noncePrefix(), parsed.noncePrefix());
        assertArrayEquals(encoded, parsed.encode());
    }

    @Test
    void segmentNonceEncodesIndexAndLastFlag() {
        FileHeader header = sample();
        assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0}, header.segmentNonce(0, false));
        assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, 0, 0, 1, 2, 1}, header.segmentNonce(258, true));
        assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, -1, -1, -1, -1, 1}, header.segmentNonce(0xFFFFFFFFL, true));
        assertThrows(IllegalStateException.class, () -> header.segmentNonce(1L << 32, false));
    }

    @Test
    void rejectsForeignFiles() {
        assertThrows(FormatException.class, () -> FileHeader.read(new ByteArrayInputStream("hello world".getBytes())));
        assertThrows(FormatException.class, () -> FileHeader.read(new ByteArrayInputStream(new byte[0])));
    }

    @Test
    void rejectsTruncatedHeader() {
        byte[] cut = Arrays.copyOf(sample().encode(), 20);
        assertThrows(FormatException.class, () -> FileHeader.read(new ByteArrayInputStream(cut)));
    }

    @Test
    void rejectsUnsupportedVersionAndKdf() {
        byte[] badVersion = sample().encode();
        badVersion[4] = 2;
        assertThrows(FormatException.class, () -> FileHeader.parse(badVersion));

        byte[] badKdf = sample().encode();
        badKdf[5] = 9;
        assertThrows(FormatException.class, () -> FileHeader.parse(badKdf));
    }

    @Test
    void rejectsHostileParameters() {
        byte[] hugeSegment = sample().encode();
        Bytes.putIntBE(Integer.MAX_VALUE, hugeSegment, 26);
        assertThrows(FormatException.class, () -> FileHeader.parse(hugeSegment));

        byte[] tinySegment = sample().encode();
        Bytes.putIntBE(16, tinySegment, 26);
        assertThrows(FormatException.class, () -> FileHeader.parse(tinySegment));

        byte[] hugeIterations = sample().encode();
        Bytes.putIntBE(-1, hugeIterations, 6);
        assertThrows(FormatException.class, () -> FileHeader.parse(hugeIterations));

        byte[] keyFileWithIterations = sample().encode();
        keyFileWithIterations[5] = (byte) KdfType.HKDF_SHA256.id();
        assertThrows(FormatException.class, () -> FileHeader.parse(keyFileWithIterations));
    }
}
