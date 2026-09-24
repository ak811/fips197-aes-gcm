package io.github.ak811.aes.selftest;

import java.util.List;

/** Published test vectors from FIPS-197, NIST SP 800-38A, the GCM specification and RFC 5869. */
public final class TestVectors {

    private TestVectors() {
    }

    public record Block(String name, String key, String plaintext, String ciphertext) {
    }

    public record Stream(String name, String key, String iv, String plaintext, String ciphertext) {
    }

    public record Aead(String name, String key, String nonce, String aad, String plaintext,
                       String ciphertext, String tag) {
    }

    public record Kdf(String name, String ikm, String salt, String info, int length, String okm) {
    }

    /** FIPS-197 Appendix B and C.1-C.3. */
    public static final List<Block> AES = List.of(
            new Block("FIPS-197 B (AES-128)",
                    "2b7e151628aed2a6abf7158809cf4f3c",
                    "3243f6a8885a308d313198a2e0370734",
                    "3925841d02dc09fbdc118597196a0b32"),
            new Block("FIPS-197 C.1 (AES-128)",
                    "000102030405060708090a0b0c0d0e0f",
                    "00112233445566778899aabbccddeeff",
                    "69c4e0d86a7b0430d8cdb78070b4c55a"),
            new Block("FIPS-197 C.2 (AES-192)",
                    "000102030405060708090a0b0c0d0e0f1011121314151617",
                    "00112233445566778899aabbccddeeff",
                    "dda97ca4864cdfe06eaf70a0ec0d7191"),
            new Block("FIPS-197 C.3 (AES-256)",
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                    "00112233445566778899aabbccddeeff",
                    "8ea2b7ca516745bfeafc49904b496089"));

    private static final String SP800_38A_PLAINTEXT =
            "6bc1bee22e409f96e93d7e117393172a"
                    + "ae2d8a571e03ac9c9eb76fac45af8e51"
                    + "30c81c46a35ce411e5fbc1191a0a52ef"
                    + "f69f2445df4f9b17ad2b417be66c3710";

    /** NIST SP 800-38A F.1.1 (ECB-AES128.Encrypt). */
    public static final Block ECB_AES128 = new Block("SP 800-38A F.1.1 ECB-AES128",
            "2b7e151628aed2a6abf7158809cf4f3c",
            SP800_38A_PLAINTEXT,
            "3ad77bb40d7a3660a89ecaf32466ef97"
                    + "f5d3d58503b9699de785895a96fdbaaf"
                    + "43b1cd7f598ece23881b00e3ed030688"
                    + "7b0c785e27e8ad3f8223207104725dd4");

    /** NIST SP 800-38A F.5.1 (CTR-AES128.Encrypt). */
    public static final Stream CTR_AES128 = new Stream("SP 800-38A F.5.1 CTR-AES128",
            "2b7e151628aed2a6abf7158809cf4f3c",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            SP800_38A_PLAINTEXT,
            "874d6191b620e3261bef6864990db6ce"
                    + "9806f66b7970fdff8617187bb9fffdff"
                    + "5ae4df3edbd5d35e5b4f09020db03eab"
                    + "1e031dda2fbe03d1792170a0f3009cee");

    private static final String GCM_P60 =
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                    + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";

    /** Test cases 1-4 and 16 from McGrew & Viega, "The Galois/Counter Mode of Operation". */
    public static final List<Aead> GCM = List.of(
            new Aead("GCM test case 1 (AES-128, empty)",
                    "00000000000000000000000000000000", "000000000000000000000000", "", "", "",
                    "58e2fccefa7e3061367f1d57a4e7455a"),
            new Aead("GCM test case 2 (AES-128, one zero block)",
                    "00000000000000000000000000000000", "000000000000000000000000", "",
                    "00000000000000000000000000000000",
                    "0388dace60b6a392f328c2b971b2fe78",
                    "ab6e47d42cec13bdf53a67b21257bddf"),
            new Aead("GCM test case 3 (AES-128, 64-byte message)",
                    "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "",
                    GCM_P60 + "1aafd255",
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                            + "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                    "4d5c2af327cd64a62cf35abd2ba6fab4"),
            new Aead("GCM test case 4 (AES-128, AAD, partial block)",
                    "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
                    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                    GCM_P60,
                    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                            + "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                    "5bc94fbc3221a5db94fae95ae7121a47"),
            new Aead("GCM test case 16 (AES-256, AAD, partial block)",
                    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                    "cafebabefacedbaddecaf888",
                    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                    GCM_P60,
                    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                            + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                    "76fc6ece0f4e1768cddf8853bb2d551b"));

    /** RFC 5869 Appendix A.1 and A.3. */
    public static final List<Kdf> HKDF = List.of(
            new Kdf("RFC 5869 A.1",
                    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                    "000102030405060708090a0b0c",
                    "f0f1f2f3f4f5f6f7f8f9",
                    42,
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
            new Kdf("RFC 5869 A.3 (empty salt and info)",
                    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                    "",
                    "",
                    42,
                    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
}
