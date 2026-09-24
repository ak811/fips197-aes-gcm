package io.github.ak811.aes.cli;

/** Invalid command-line usage; reported with a hint to run {@code help}. */
final class UsageException extends Exception {

    private static final long serialVersionUID = 1L;

    UsageException(String message) {
        super(message);
    }
}
