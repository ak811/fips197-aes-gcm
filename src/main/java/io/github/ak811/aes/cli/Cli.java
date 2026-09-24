package io.github.ak811.aes.cli;

import io.github.ak811.aes.aead.Aead;
import io.github.ak811.aes.aead.AuthenticationException;
import io.github.ak811.aes.aead.Engine;
import io.github.ak811.aes.demo.EcbLeakageDemo;
import io.github.ak811.aes.format.EncryptOptions;
import io.github.ak811.aes.format.FileCrypto;
import io.github.ak811.aes.format.FileHeader;
import io.github.ak811.aes.format.FormatException;
import io.github.ak811.aes.format.KdfType;
import io.github.ak811.aes.format.KeyFiles;
import io.github.ak811.aes.format.KeySource;
import io.github.ak811.aes.io.AtomicFileOutput;
import io.github.ak811.aes.selftest.KnownAnswerTests;
import io.github.ak811.aes.util.Bytes;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Command-line front end. {@link #run} returns an exit code instead of calling {@code System.exit}. */
public final class Cli {

    public static final int EXIT_OK = 0;
    public static final int EXIT_USAGE = 1;
    public static final int EXIT_AUTH = 2;
    public static final int EXIT_IO = 3;
    public static final int EXIT_SELFTEST = 4;

    static final String PROGRAM = "aesf";

    private static final String STDIO = "-";
    private static final Set<String> KEY_OPTIONS = Set.of("--key-file", "--password-file", "--password-env");

    private final InputStream stdin;
    private final PrintStream stdout;
    private final PrintStream stderr;
    private final Map<String, String> env;

    public Cli(InputStream stdin, PrintStream stdout, PrintStream stderr, Map<String, String> env) {
        this.stdin = Objects.requireNonNull(stdin);
        this.stdout = Objects.requireNonNull(stdout);
        this.stderr = Objects.requireNonNull(stderr);
        this.env = Objects.requireNonNull(env);
    }

    public int run(String... argv) {
        if (argv.length == 0) {
            stderr.print(usage());
            return EXIT_USAGE;
        }
        List<String> rest = Arrays.asList(argv).subList(1, argv.length);
        try {
            switch (argv[0]) {
                case "encrypt":
                    return encrypt(rest);
                case "decrypt":
                    return decrypt(rest);
                case "keygen":
                    return keygen(rest);
                case "inspect":
                    return inspect(rest);
                case "selftest":
                    return selftest(rest);
                case "bench":
                    return bench(rest);
                case "ecb-demo":
                    return ecbDemo(rest);
                case "help":
                case "-h":
                case "--help":
                    stdout.print(usage());
                    return EXIT_OK;
                case "version":
                case "--version":
                    stdout.println(PROGRAM + " " + version());
                    return EXIT_OK;
                default:
                    throw new UsageException("unknown command '" + argv[0] + "'");
            }
        } catch (UsageException e) {
            stderr.println("error: " + e.getMessage());
            stderr.println("Run '" + PROGRAM + " help' for usage.");
            return EXIT_USAGE;
        } catch (AuthenticationException e) {
            stderr.println("error: decryption failed: wrong password or key, or the file is corrupted or has been tampered with");
            return EXIT_AUTH;
        } catch (IllegalArgumentException e) {
            stderr.println("error: " + e.getMessage());
            return EXIT_USAGE;
        } catch (IOException e) {
            stderr.println("error: " + describe(e));
            return EXIT_IO;
        }
    }

    // ---------------------------------------------------------------- commands

    private int encrypt(List<String> tokens) throws UsageException, IOException, AuthenticationException {
        Args args = Args.parse(tokens,
                union(KEY_OPTIONS, Set.of("--output", "--iterations", "--segment-size", "--engine")),
                Set.of("--force"));
        String input = args.single("input");
        String output = args.option("--output", input.equals(STDIO) ? STDIO : input + FileCrypto.FILE_EXTENSION);

        EncryptOptions options = EncryptOptions.defaults()
                .withEngine(engine(args))
                .withIterations(args.intOption("--iterations", EncryptOptions.DEFAULT_ITERATIONS, false))
                .withSegmentSize(args.intOption("--segment-size", EncryptOptions.DEFAULT_SEGMENT_SIZE, true));

        checkDistinct(input, output);
        try (KeySource key = keySource(args, true)) {
            transform(input, output, args.flag("--force"), (in, out) -> FileCrypto.encrypt(in, out, key, options));
        }
        status("encrypted", input, output);
        return EXIT_OK;
    }

    private int decrypt(List<String> tokens) throws UsageException, IOException, AuthenticationException {
        Args args = Args.parse(tokens, union(KEY_OPTIONS, Set.of("--output", "--engine")), Set.of("--force"));
        String input = args.single("input");
        String output = args.option("--output");
        if (output == null) {
            if (input.equals(STDIO)) {
                output = STDIO;
            } else if (input.endsWith(FileCrypto.FILE_EXTENSION) && input.length() > FileCrypto.FILE_EXTENSION.length()) {
                output = input.substring(0, input.length() - FileCrypto.FILE_EXTENSION.length());
            } else {
                throw new UsageException("cannot infer an output name for '" + input + "'; pass --output");
            }
        }
        Engine engine = engine(args);

        checkDistinct(input, output);
        try (KeySource key = keySource(args, false)) {
            transform(input, output, args.flag("--force"), (in, out) -> FileCrypto.decrypt(in, out, key, engine));
        }
        status("decrypted", input, output);
        return EXIT_OK;
    }

    private int keygen(List<String> tokens) throws UsageException, IOException {
        Args args = Args.parse(tokens, Set.of(), Set.of("--force"));
        Path path = Path.of(args.single("output"));
        KeyFiles.generate(path, args.flag("--force"), new SecureRandom());
        stderr.println("wrote a new 256-bit key to " + path);
        stderr.println("keep it secret and back it up: files encrypted with it cannot be recovered without it");
        return EXIT_OK;
    }

    private int inspect(List<String> tokens) throws UsageException, IOException {
        Args args = Args.parse(tokens, Set.of(), Set.of());
        String input = args.single("input");
        FileHeader header;
        try (InputStream in = openInput(input)) {
            header = FileHeader.read(in);
        }
        HexFormat hex = HexFormat.of();
        stdout.println("format:        AESF v" + FileHeader.VERSION + " (AES-256-GCM, segmented stream)");
        stdout.println("protected by:  " + header.kdf().description());
        if (header.kdf() == KdfType.PBKDF2_HMAC_SHA256) {
            stdout.println("iterations:    " + header.iterations());
        }
        stdout.println("salt:          " + hex.formatHex(header.salt()));
        stdout.println("segment size:  " + header.segmentSize() + " bytes");
        stdout.println("nonce prefix:  " + hex.formatHex(header.noncePrefix()));
        if (!input.equals(STDIO)) {
            long size = Files.size(Path.of(input));
            long perSegment = header.segmentSize() + (long) Aead.TAG_LENGTH;
            long body = size - FileHeader.LENGTH;
            long segments = Math.max(1, (body + perSegment - 1) / perSegment);
            stdout.println("file size:     " + size + " bytes (" + segments + " segment" + (segments == 1 ? "" : "s")
                    + ", plaintext ~" + Math.max(0, body - segments * Aead.TAG_LENGTH) + " bytes)");
        }
        return EXIT_OK;
    }

    private int selftest(List<String> tokens) throws UsageException {
        Args.parse(tokens, Set.of(), Set.of());
        return KnownAnswerTests.run(stdout) ? EXIT_OK : EXIT_SELFTEST;
    }

    private int bench(List<String> tokens) throws UsageException {
        Args args = Args.parse(tokens, Set.of("--size"), Set.of());
        int mib = args.intOption("--size", 64, false);
        if (mib < 1 || mib > 4096) {
            throw new UsageException("--size must be between 1 and 4096 MiB");
        }
        byte[] segment = new byte[EncryptOptions.DEFAULT_SEGMENT_SIZE];
        new SecureRandom().nextBytes(segment);
        int segments = (int) ((long) mib * 1024 * 1024 / segment.length);
        stdout.printf("AES-256-GCM, %d KiB segments, %d MiB per engine%n", segment.length / 1024, mib);
        for (Engine engine : Engine.values()) {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            try (Aead aead = engine.aesGcm(key)) {
                byte[] nonce = new byte[Aead.NONCE_LENGTH];
                for (int i = 0; i < Math.min(segments, 64); i++) { // warm-up for the JIT
                    Bytes.putIntBE(i, nonce, 0);
                    aead.encrypt(nonce, segment, null);
                }
                nonce[4] = 1;
                long start = System.nanoTime();
                for (int i = 0; i < segments; i++) {
                    Bytes.putIntBE(i, nonce, 0);
                    aead.encrypt(nonce, segment, null);
                }
                double seconds = (System.nanoTime() - start) / 1e9;
                stdout.printf("  %-10s %8.1f MiB/s%n", engine.cliName(), mib / seconds);
            } finally {
                Bytes.zeroize(key);
            }
        }
        return EXIT_OK;
    }

    private int ecbDemo(List<String> tokens) throws UsageException, IOException {
        Args args = Args.parse(tokens, Set.of("--output"), Set.of());
        if (args.positionals().size() > 1) {
            throw new UsageException("expected at most one image argument");
        }
        Path image = args.positionals().isEmpty() ? null : Path.of(args.positionals().get(0));
        Path outDir = Path.of(args.option("--output", "."));
        for (Path p : EcbLeakageDemo.run(image, outDir)) {
            stdout.println("wrote " + p);
        }
        stdout.println("Open the -ecb and -ctr images side by side: ECB preserves the picture, CTR does not.");
        return EXIT_OK;
    }

    // ---------------------------------------------------------------- helpers

    @FunctionalInterface
    private interface StreamOp {
        void apply(InputStream in, OutputStream out) throws IOException, AuthenticationException;
    }

    /** Runs {@code op} from input to output; file output only appears if {@code op} succeeds. */
    private void transform(String input, String output, boolean force, StreamOp op)
            throws IOException, AuthenticationException {
        try (InputStream in = openInput(input)) {
            if (output.equals(STDIO)) {
                OutputStream out = new BufferedOutputStream(new FilterOutputStream(stdout) {
                    @Override
                    public void close() throws IOException {
                        flush();
                    }
                });
                op.apply(in, out);
                out.flush();
                return;
            }
            try (AtomicFileOutput out = AtomicFileOutput.create(Path.of(output), force)) {
                op.apply(in, out.stream());
                out.commit();
            }
        }
    }

    private InputStream openInput(String input) throws IOException {
        if (input.equals(STDIO)) {
            return new FilterInputStream(stdin) {
                @Override
                public void close() {
                    // never close the process's stdin
                }
            };
        }
        Path path = Path.of(input);
        if (Files.isDirectory(path)) {
            throw new IOException(input + " is a directory");
        }
        return new BufferedInputStream(Files.newInputStream(path), 64 * 1024);
    }

    private KeySource keySource(Args args, boolean confirmPassword) throws UsageException, IOException {
        long given = KEY_OPTIONS.stream().filter(o -> args.option(o) != null).count();
        if (given > 1) {
            throw new UsageException("use only one of --key-file, --password-file, --password-env");
        }
        if (args.option("--key-file") != null) {
            byte[] key = KeyFiles.read(Path.of(args.option("--key-file")));
            try {
                return KeySource.rawKey(key);
            } finally {
                Bytes.zeroize(key);
            }
        }
        char[] password;
        if (args.option("--password-file") != null) {
            password = Passwords.fromFile(Path.of(args.option("--password-file")));
        } else if (args.option("--password-env") != null) {
            password = Passwords.fromEnv(env, args.option("--password-env"));
        } else {
            password = Passwords.prompt(confirmPassword, stderr);
        }
        try {
            return KeySource.password(password);
        } finally {
            Bytes.zeroize(password);
        }
    }

    private static Engine engine(Args args) {
        return Engine.parse(args.option("--engine", Engine.JCA.cliName()));
    }

    private static void checkDistinct(String input, String output) throws UsageException, IOException {
        if (input.equals(STDIO) || output.equals(STDIO)) {
            return;
        }
        Path in = Path.of(input);
        Path out = Path.of(output);
        boolean same = Files.exists(in) && Files.exists(out)
                ? Files.isSameFile(in, out)
                : in.toAbsolutePath().normalize().equals(out.toAbsolutePath().normalize());
        if (same) {
            throw new UsageException("input and output must be different files");
        }
    }

    private void status(String verb, String input, String output) {
        if (!output.equals(STDIO)) {
            stderr.println(verb + " " + (input.equals(STDIO) ? "stdin" : input) + " -> " + output);
        }
    }

    private static String describe(IOException e) {
        if (e instanceof NoSuchFileException) {
            return "no such file: " + e.getMessage();
        }
        if (e instanceof AccessDeniedException) {
            return "permission denied: " + e.getMessage();
        }
        if (e instanceof FileAlreadyExistsException) {
            return e.getMessage() + " already exists (use --force to overwrite)";
        }
        if (e instanceof FormatException) {
            return e.getMessage();
        }
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        HashSet<String> all = new HashSet<>(a);
        all.addAll(b);
        return all;
    }

    private static String version() {
        String v = Cli.class.getPackage().getImplementationVersion();
        return v != null ? v : "dev";
    }

    static String usage() {
        return String.join(System.lineSeparator(),
                "Usage: " + PROGRAM + " <command> [options]",
                "",
                "Commands:",
                "  encrypt <input>   Encrypt a file (use - for stdin)",
                "  decrypt <input>   Decrypt a file (use - for stdin)",
                "  keygen <file>     Generate a random 256-bit key file",
                "  inspect <file>    Show an encrypted file's header (no key needed)",
                "  selftest          Run the known-answer tests on this machine",
                "  bench             Measure throughput of each engine",
                "  ecb-demo [image]  Show why ECB mode leaks structure",
                "  help | version",
                "",
                "Key options (encrypt/decrypt; default is an interactive password prompt):",
                "  --key-file <file>        Use a key file created with 'keygen'",
                "  --password-file <file>   Read the password from the first line of a file",
                "  --password-env <VAR>     Read the password from an environment variable",
                "",
                "Other options:",
                "  -o, --output <path>      Output path (- for stdout). Defaults: <input>.aesf / strip .aesf",
                "  -f, --force              Overwrite an existing output file",
                "  --engine jca|reference   AES implementation (default: jca, hardware-accelerated)",
                "  --iterations <n>         PBKDF2 iterations for passwords (default "
                        + EncryptOptions.DEFAULT_ITERATIONS + ", min " + EncryptOptions.MIN_ITERATIONS + ")",
                "  --segment-size <n>[K|M]  Plaintext bytes per authenticated segment (default 64K)",
                "  --size <MiB>             Data per engine for 'bench' (default 64)",
                "",
                "Exit codes: 0 ok, 1 usage error, 2 authentication failed, 3 I/O error, 4 self-test failed",
                "");
    }
}
