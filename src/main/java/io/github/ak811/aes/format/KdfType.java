package io.github.ak811.aes.format;

/** How the per-file key is derived. Stored as one byte in the file header. */
public enum KdfType {

    /** From a password, with PBKDF2-HMAC-SHA256 and the header's iteration count. */
    PBKDF2_HMAC_SHA256(1, "password (PBKDF2-HMAC-SHA256)"),

    /** From a 256-bit key file, with HKDF-SHA256. */
    HKDF_SHA256(2, "key file (HKDF-SHA256)");

    private final int id;
    private final String description;

    KdfType(int id, String description) {
        this.id = id;
        this.description = description;
    }

    public int id() {
        return id;
    }

    public String description() {
        return description;
    }

    public static KdfType fromId(int id) throws FormatException {
        for (KdfType t : values()) {
            if (t.id == id) {
                return t;
            }
        }
        throw new FormatException("unknown key-derivation type " + id);
    }
}
