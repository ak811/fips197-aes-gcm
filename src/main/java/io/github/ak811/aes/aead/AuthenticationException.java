package io.github.ak811.aes.aead;

import java.security.GeneralSecurityException;

/**
 * Thrown when a ciphertext fails authentication: the key or password is wrong, or the data was
 * corrupted, truncated, reordered or tampered with. These causes are deliberately indistinguishable.
 */
public class AuthenticationException extends GeneralSecurityException {

    private static final long serialVersionUID = 1L;

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
