package io.github.ak811.aes.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class CliTest {

    private static final String FAST = "100000"; // minimum iterations, keeps the tests quick

    private record Result(int code, byte[] stdout, String stderr) {
        String out() {
            return new String(stdout, StandardCharsets.UTF_8);
        }
    }

    private static Result run(byte[] stdin, String... args) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = new Cli(new ByteArrayInputStream(stdin),
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8),
                Map.of("AESF_PASSWORD", "env password 123")).run(args);
        return new Result(code, out.toByteArray(), err.toString(StandardCharsets.UTF_8));
    }

    private static Result run(String... args) {
        return run(new byte[0], args);
    }

    private static Path tempDir() throws IOException {
        return Files.createTempDirectory("aesf-cli-test");
    }

    private static Path randomFile(Path dir, String name, int size) throws IOException {
        byte[] data = new byte[size];
        new Random(size).nextBytes(data);
        return Files.write(dir.resolve(name), data);
    }

    private static boolean hasPartialFiles(Path dir) throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.anyMatch(p -> p.getFileName().toString().endsWith(".partial"));
        }
    }

    @Test
    void passwordFileRoundTrip() throws Exception {
        Path dir = tempDir();
        Path plain = randomFile(dir, "report.pdf", 200_000);
        Path pw = Files.writeString(dir.resolve("pw.txt"), "a long passphrase\n");

        Result enc = run("encrypt", plain.toString(), "--password-file", pw.toString(), "--iterations", FAST);
        assertEquals(Cli.EXIT_OK, enc.code(), enc.stderr());
        Path encrypted = dir.resolve("report.pdf.aesf");
        assertTrue(Files.exists(encrypted));

        Path restored = dir.resolve("restored.pdf");
        Result dec = run("decrypt", encrypted.toString(), "-o", restored.toString(), "--password-file", pw.toString());
        assertEquals(Cli.EXIT_OK, dec.code(), dec.stderr());
        assertArrayEquals(Files.readAllBytes(plain), Files.readAllBytes(restored));
    }

    @Test
    void keyFileRoundTripAcrossEngines() throws Exception {
        Path dir = tempDir();
        Path key = dir.resolve("secret.key");
        assertEquals(Cli.EXIT_OK, run("keygen", key.toString()).code());
        Path plain = randomFile(dir, "data.bin", 70_000);

        assertEquals(Cli.EXIT_OK, run("encrypt", plain.toString(), "--key-file", key.toString(), "--engine", "reference").code());
        Files.delete(plain);
        Result dec = run("decrypt", dir.resolve("data.bin.aesf").toString(), "--key-file", key.toString(), "--engine", "jca");
        assertEquals(Cli.EXIT_OK, dec.code(), dec.stderr());
        byte[] expected = new byte[70_000];
        new Random(70_000).nextBytes(expected);
        assertArrayEquals(expected, Files.readAllBytes(plain));
    }

    @Test
    void wrongPasswordFailsCleanly() throws Exception {
        Path dir = tempDir();
        Path plain = randomFile(dir, "notes.txt", 5000);
        assertEquals(Cli.EXIT_OK, run("encrypt", plain.toString(), "--password-env", "AESF_PASSWORD", "--iterations", FAST).code());

        Path wrong = Files.writeString(dir.resolve("wrong.txt"), "not the password");
        Path out = dir.resolve("out.txt");
        Result dec = run("decrypt", dir.resolve("notes.txt.aesf").toString(), "-o", out.toString(), "--password-file", wrong.toString());
        assertEquals(Cli.EXIT_AUTH, dec.code());
        assertTrue(dec.stderr().contains("decryption failed"));
        assertFalse(Files.exists(out), "no output may be left behind on failure");
        assertFalse(hasPartialFiles(dir), "temporary file must be cleaned up");
    }

    @Test
    void refusesToOverwriteWithoutForce() throws Exception {
        Path dir = tempDir();
        Path plain = randomFile(dir, "a.bin", 100);
        Path existing = Files.writeString(dir.resolve("a.bin.aesf"), "precious");
        Path key = dir.resolve("k");
        run("keygen", key.toString());

        Result first = run("encrypt", plain.toString(), "--key-file", key.toString());
        assertEquals(Cli.EXIT_IO, first.code());
        assertTrue(first.stderr().contains("already exists"));
        assertEquals("precious", Files.readString(existing));

        assertEquals(Cli.EXIT_OK, run("encrypt", plain.toString(), "--key-file", key.toString(), "--force").code());
        assertFalse(Files.readString(existing, StandardCharsets.ISO_8859_1).equals("precious"));
    }

    @Test
    void streamsThroughStdinAndStdout() throws Exception {
        Path dir = tempDir();
        Path key = dir.resolve("k");
        run("keygen", key.toString());
        byte[] data = "piped data\n".repeat(10_000).getBytes(StandardCharsets.UTF_8);

        Result enc = run(data, "encrypt", "-", "--key-file", key.toString());
        assertEquals(Cli.EXIT_OK, enc.code(), enc.stderr());
        Result dec = run(enc.stdout(), "decrypt", "-", "--key-file", key.toString());
        assertEquals(Cli.EXIT_OK, dec.code(), dec.stderr());
        assertArrayEquals(data, dec.stdout());
    }

    @Test
    void inspectShowsHeaderWithoutKey() throws Exception {
        Path dir = tempDir();
        Path plain = randomFile(dir, "x", 10);
        run("encrypt", plain.toString(), "--password-env", "AESF_PASSWORD", "--iterations", "123456");
        Result r = run("inspect", dir.resolve("x.aesf").toString());
        assertEquals(Cli.EXIT_OK, r.code());
        assertTrue(r.out().contains("PBKDF2-HMAC-SHA256"));
        assertTrue(r.out().contains("123456"));
    }

    @Test
    void reportsUsageErrors() throws Exception {
        assertEquals(Cli.EXIT_USAGE, run().code());
        assertEquals(Cli.EXIT_USAGE, run("frobnicate").code());
        assertEquals(Cli.EXIT_USAGE, run("encrypt").code());
        assertEquals(Cli.EXIT_USAGE, run("encrypt", "a", "--bogus").code());
        assertEquals(Cli.EXIT_USAGE, run("encrypt", "a", "--key-file", "k", "--password-env", "AESF_PASSWORD").code());
        assertEquals(Cli.EXIT_USAGE, run("decrypt", "file.bin", "--key-file", "k").code());
        assertEquals(Cli.EXIT_USAGE, run("encrypt", "a", "--engine", "fast").code());

        Path dir = tempDir();
        Path plain = randomFile(dir, "p", 10);
        assertEquals(Cli.EXIT_USAGE, run("encrypt", plain.toString(), "--password-env", "AESF_PASSWORD",
                "--iterations", "10").code());
        assertEquals(Cli.EXIT_USAGE, run("encrypt", plain.toString(), "-o", plain.toString(),
                "--password-env", "AESF_PASSWORD").code());
    }

    @Test
    void reportsMissingInputAndForeignFiles() throws Exception {
        Path dir = tempDir();
        Result missing = run("inspect", dir.resolve("nope.aesf").toString());
        assertEquals(Cli.EXIT_IO, missing.code());
        assertTrue(missing.stderr().contains("no such file"));

        Path foreign = Files.writeString(dir.resolve("foreign.aesf"), "definitely not encrypted");
        Result r = run("decrypt", foreign.toString(), "--password-env", "AESF_PASSWORD");
        assertEquals(Cli.EXIT_IO, r.code());
        assertTrue(r.stderr().contains("not an encrypted file"));
    }

    @Test
    void helpAndSelftest() {
        Result help = run("help");
        assertEquals(Cli.EXIT_OK, help.code());
        assertTrue(help.out().contains("Usage: aesf"));

        Result selftest = run("selftest");
        assertEquals(Cli.EXIT_OK, selftest.code(), selftest.out());
        assertTrue(selftest.out().contains("0 failed"));
    }
}
