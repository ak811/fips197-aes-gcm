package io.github.ak811.aes.cli;

import io.github.ak811.aes.util.Bytes;
import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;

/**
 * Password input. Passwords are never accepted as command-line arguments, because those are visible
 * to other users through the process list and end up in shell history.
 */
final class Passwords {

    private static final int RECOMMENDED_LENGTH = 12;

    private Passwords() {
    }

    /** Prompts on the terminal without echo; asks twice when {@code confirm} is set. */
    static char[] prompt(boolean confirm, PrintStream err) throws UsageException {
        Console console = System.console();
        if (console == null) {
            throw new UsageException("no interactive terminal available; use --password-file, --password-env or --key-file");
        }
        char[] first = console.readPassword("Password: ");
        if (first == null || first.length == 0) {
            Bytes.zeroize(first);
            throw new UsageException("no password entered");
        }
        if (confirm) {
            char[] second = console.readPassword("Confirm password: ");
            boolean match = Arrays.equals(first, second);
            Bytes.zeroize(second);
            if (!match) {
                Bytes.zeroize(first);
                throw new UsageException("passwords do not match");
            }
            if (first.length < RECOMMENDED_LENGTH) {
                err.println("warning: short passwords are easy to guess; prefer " + RECOMMENDED_LENGTH
                        + "+ characters or a key file (see 'keygen')");
            }
        }
        return first;
    }

    /** First line of a UTF-8 file, without the line terminator. */
    static char[] fromFile(Path path) throws IOException, UsageException {
        byte[] raw = Files.readAllBytes(path);
        CharBuffer decoded = null;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw));
            int end = 0;
            while (end < decoded.length() && decoded.charAt(end) != '\n' && decoded.charAt(end) != '\r') {
                end++;
            }
            if (end == 0) {
                throw new UsageException("password file " + path + " is empty");
            }
            char[] password = new char[end];
            decoded.get(password);
            return password;
        } catch (CharacterCodingException e) {
            throw new UsageException("password file " + path + " is not valid UTF-8");
        } finally {
            Bytes.zeroize(raw);
            if (decoded != null && decoded.hasArray()) {
                Arrays.fill(decoded.array(), '\0');
            }
        }
    }

    static char[] fromEnv(Map<String, String> env, String name) throws UsageException {
        String value = env.get(name);
        if (value == null || value.isEmpty()) {
            throw new UsageException("environment variable " + name + " is not set or is empty");
        }
        return value.toCharArray();
    }
}
