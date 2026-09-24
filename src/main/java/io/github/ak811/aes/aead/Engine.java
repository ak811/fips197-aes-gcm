package io.github.ak811.aes.aead;

import java.util.Locale;

/**
 * Selects the AES-GCM implementation. Both produce byte-identical output, so files encrypted with
 * one engine decrypt with the other.
 */
public enum Engine {

    /** Hardware-accelerated, constant-time JDK implementation. Default. */
    JCA("jca") {
        @Override
        public Aead aesGcm(byte[] key) {
            return new JcaAesGcm(key);
        }
    },

    /** The from-scratch {@link io.github.ak811.aes.core.Aes} + {@link Gcm} in this project. */
    REFERENCE("reference") {
        @Override
        public Aead aesGcm(byte[] key) {
            return Gcm.withAes(key);
        }
    };

    private final String cliName;

    Engine(String cliName) {
        this.cliName = cliName;
    }

    public abstract Aead aesGcm(byte[] key);

    public String cliName() {
        return cliName;
    }

    public static Engine parse(String name) {
        for (Engine e : values()) {
            if (e.cliName.equals(name.toLowerCase(Locale.ROOT))) {
                return e;
            }
        }
        throw new IllegalArgumentException("unknown engine '" + name + "' (expected 'jca' or 'reference')");
    }
}
