package io.github.ak811.aes.selftest;

import io.github.ak811.aes.aead.Aead;
import io.github.ak811.aes.aead.AuthenticationException;
import io.github.ak811.aes.aead.Engine;
import io.github.ak811.aes.core.Aes;
import io.github.ak811.aes.format.EncryptOptions;
import io.github.ak811.aes.format.FileCrypto;
import io.github.ak811.aes.format.KeySource;
import io.github.ak811.aes.kdf.Hkdf;
import io.github.ak811.aes.mode.Ctr;
import io.github.ak811.aes.mode.Ecb;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

/**
 * Runs the published test vectors against every implementation, plus a file round trip and a
 * tamper check per engine. Exposed as the {@code selftest} CLI command so a deployment can verify
 * the build on its own JVM and hardware before trusting it.
 */
public final class KnownAnswerTests {

    private static final HexFormat HEX = HexFormat.of();

    private final PrintStream log;
    private int passed;
    private int failed;

    private KnownAnswerTests(PrintStream log) {
        this.log = log;
    }

    /** @return {@code true} if every check passed */
    public static boolean run(PrintStream log) {
        KnownAnswerTests t = new KnownAnswerTests(log);
        t.runAll();
        log.printf("%n%d passed, %d failed%n", t.passed, t.failed);
        return t.failed == 0;
    }

    private void runAll() {
        for (TestVectors.Block v : TestVectors.AES) {
            check("AES block", v.name(), () -> {
                try (Aes aes = new Aes(hex(v.key()))) {
                    byte[] pt = hex(v.plaintext());
                    byte[] ct = new byte[16];
                    aes.encryptBlock(pt, 0, ct, 0);
                    byte[] back = new byte[16];
                    aes.decryptBlock(ct, 0, back, 0);
                    return Arrays.equals(ct, hex(v.ciphertext())) && Arrays.equals(back, pt);
                }
            });
        }

        TestVectors.Block ecb = TestVectors.ECB_AES128;
        check("ECB", ecb.name(), () -> {
            try (Aes aes = new Aes(hex(ecb.key()))) {
                byte[] ct = Ecb.encrypt(aes, hex(ecb.plaintext()));
                return Arrays.equals(ct, hex(ecb.ciphertext()))
                        && Arrays.equals(Ecb.decrypt(aes, ct), hex(ecb.plaintext()));
            }
        });

        TestVectors.Stream ctr = TestVectors.CTR_AES128;
        check("CTR", ctr.name(), () -> {
            try (Aes aes = new Aes(hex(ctr.key()))) {
                return Arrays.equals(Ctr.apply(aes, hex(ctr.iv()), hex(ctr.plaintext())), hex(ctr.ciphertext()));
            }
        });

        for (TestVectors.Kdf v : TestVectors.HKDF) {
            check("HKDF", v.name(), () -> Arrays.equals(
                    Hkdf.deriveSha256(hex(v.ikm()), hex(v.salt()), hex(v.info()), v.length()), hex(v.okm())));
        }

        for (Engine engine : Engine.values()) {
            for (TestVectors.Aead v : TestVectors.GCM) {
                check("GCM " + engine.cliName(), v.name(), () -> gcmVector(engine, v));
            }
            check("File " + engine.cliName(), "round trip + tamper detection", () -> fileRoundTrip(engine));
        }
    }

    private static boolean gcmVector(Engine engine, TestVectors.Aead v) throws AuthenticationException {
        byte[] expected = concat(hex(v.ciphertext()), hex(v.tag()));
        try (Aead aead = engine.aesGcm(hex(v.key()))) {
            byte[] sealed = aead.encrypt(hex(v.nonce()), hex(v.plaintext()), hex(v.aad()));
            byte[] opened = aead.decrypt(hex(v.nonce()), expected, hex(v.aad()));
            return Arrays.equals(sealed, expected) && Arrays.equals(opened, hex(v.plaintext()));
        }
    }

    private static boolean fileRoundTrip(Engine engine) throws Exception {
        byte[] plaintext = new byte[10_000];
        new Random(1).nextBytes(plaintext);
        byte[] rawKey = new byte[KeySource.RAW_KEY_LENGTH];
        new Random(2).nextBytes(rawKey);
        EncryptOptions options = EncryptOptions.defaults().withEngine(engine).withSegmentSize(4096);

        ByteArrayOutputStream encrypted = new ByteArrayOutputStream();
        try (KeySource key = KeySource.rawKey(rawKey)) {
            FileCrypto.encrypt(new ByteArrayInputStream(plaintext), encrypted, key, options);
            byte[] ct = encrypted.toByteArray();

            ByteArrayOutputStream decrypted = new ByteArrayOutputStream();
            FileCrypto.decrypt(new ByteArrayInputStream(ct), decrypted, key, engine);
            if (!Arrays.equals(decrypted.toByteArray(), plaintext)) {
                return false;
            }

            ct[ct.length / 2] ^= 1;
            try {
                FileCrypto.decrypt(new ByteArrayInputStream(ct), new ByteArrayOutputStream(), key, engine);
                return false;
            } catch (AuthenticationException expected) {
                return true;
            }
        }
    }

    private void check(String group, String description, Check check) {
        String name = String.format("%-16s %s", group, description);
        boolean ok;
        String detail = "";
        try {
            ok = check.run();
        } catch (Exception | AssertionError e) {
            ok = false;
            detail = " (" + e + ")";
        }
        if (ok) {
            passed++;
            log.println("  PASS  " + name);
        } else {
            failed++;
            log.println("  FAIL  " + name + detail);
        }
    }

    @FunctionalInterface
    private interface Check {
        boolean run() throws Exception;
    }

    private static byte[] hex(String s) {
        return HEX.parseHex(s);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
