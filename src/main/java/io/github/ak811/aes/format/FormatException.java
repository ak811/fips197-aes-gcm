package io.github.ak811.aes.format;

import java.io.IOException;

/** The input is not a file this tool produced, or uses an unsupported version or parameters. */
public class FormatException extends IOException {

    private static final long serialVersionUID = 1L;

    public FormatException(String message) {
        super(message);
    }
}
