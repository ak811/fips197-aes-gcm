## FIPS-197 AES + SP 800-38D GCM from scratch in Java; streaming AES-256-GCM file CLI with PBKDF2/HKDF

Authenticated file encryption (AES-256-GCM) with a from-scratch AES and GCM implementation that is verified byte-for-byte against the official test vectors and the JDK.

The project has two halves that share one interface:

- **A reference implementation, written from scratch**: the AES block cipher (FIPS-197, 128/192/256-bit keys), CTR mode, and GCM with a constant-time GHASH over GF(2^128). No crypto library code is used in these classes.
- **A production CLI and library** built on top: a streaming, tamper-evident file format, PBKDF2/HKDF key derivation, atomic writes, and a hardware-accelerated default engine.

Both engines produce identical output, so a file encrypted with one decrypts with the other. That property is tested on thousands of random inputs.

```
$ aesf encrypt taxes-2025.pdf
Password:
Confirm password:
encrypted taxes-2025.pdf -> taxes-2025.pdf.aesf

$ aesf decrypt taxes-2025.pdf.aesf
Password:
decrypted taxes-2025.pdf.aesf -> taxes-2025.pdf
```

## Features

- **AES-256-GCM** authenticated encryption. Any modification, truncation, extension or reordering of an encrypted file is detected.
- **Streaming**: files of any size are processed in constant memory, in 64 KiB authenticated segments.
- **Passwords or key files**: PBKDF2-HMAC-SHA256 (600,000 iterations by default) for passwords; HKDF-SHA256 for random 256-bit key files made with `keygen`.
- **Safe output**: results are written to a temporary file and renamed into place only on success. A failed decryption never leaves partial plaintext behind, and existing files are never overwritten without `--force`.
- **No secrets on the command line**: passwords come from a no-echo prompt, a file, or an environment variable, never from arguments visible in `ps` or shell history.
- **Pipes**: `-` reads stdin or writes stdout, so the tool slots into `tar`/`ssh`/backup pipelines.
- **Self-test**: `aesf selftest` runs the published test vectors against every implementation on the machine it will run on.
- **Zero runtime dependencies**: plain Java 17+. JUnit 5 is used only for tests.

## Quick start

Requires Java 17 or newer and Maven.

```bash
mvn -B verify                    # compile and run the test suite
java -jar target/aesf.jar help   # the CLI

alias aesf='java -jar /path/to/target/aesf.jar'
```

### Common tasks

```bash
# Password-based (prompts twice on encrypt, once on decrypt)
aesf encrypt notes.txt                      # -> notes.txt.aesf
aesf decrypt notes.txt.aesf                 # -> notes.txt
aesf decrypt notes.txt.aesf -o copy.txt

# Key file instead of a password (best for scripts and backups)
aesf keygen backup.key                      # 256-bit random key, owner-only permissions
aesf encrypt db.dump --key-file backup.key
aesf decrypt db.dump.aesf --key-file backup.key

# Non-interactive passwords
aesf encrypt report.pdf --password-file ~/.secrets/pw
AESF_PW='...' aesf encrypt report.pdf --password-env AESF_PW

# Pipelines
tar czf - photos/ | aesf encrypt - --key-file backup.key > photos.tgz.aesf
aesf decrypt photos.tgz.aesf -o - --key-file backup.key | tar xzf -

# Look at a file's parameters without a key
aesf inspect db.dump.aesf
```

### Commands

| Command | Description |
|---|---|
| `encrypt <input>` | Encrypt a file (`-` for stdin). Output defaults to `<input>.aesf`. |
| `decrypt <input>` | Decrypt a file (`-` for stdin). Output defaults to the input without `.aesf`. |
| `keygen <file>` | Write a new random 256-bit key (Base64) with owner-only permissions. |
| `inspect <file>` | Print the header (KDF, iterations, salt, segment size). No key needed. |
| `selftest` | Run all known-answer tests on this JVM and hardware. |
| `bench` | Measure throughput of both engines (`--size <MiB>`). |
| `ecb-demo [image]` | Show why ECB mode is insecure (see below). |

| Option | Description |
|---|---|
| `--key-file <file>` / `--password-file <file>` / `--password-env <VAR>` | Key source. Default: interactive prompt. |
| `-o, --output <path>` | Output path, or `-` for stdout. |
| `-f, --force` | Overwrite an existing output file. |
| `--engine jca\|reference` | AES implementation. Default `jca`. |
| `--iterations <n>` | PBKDF2 iterations for passwords (min 100,000; default 600,000). |
| `--segment-size <n>[K\|M]` | Plaintext bytes per segment (4K to 16M; default 64K). |

Exit codes: `0` success, `1` usage error, `2` authentication failed (wrong key/password or tampered file), `3` I/O error, `4` self-test failure.

## Security design

### File format (version 1)

```
header (37 bytes) || segment 0 || segment 1 || ... || segment n
```

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Magic `AESF` |
| 4 | 1 | Format version (`1`) |
| 5 | 1 | Key derivation: `1` = PBKDF2-HMAC-SHA256 (password), `2` = HKDF-SHA256 (key file) |
| 6 | 4 | PBKDF2 iterations, big-endian (`0` for key files) |
| 10 | 16 | Random salt |
| 26 | 4 | Plaintext segment size, big-endian |
| 30 | 7 | Random nonce prefix |

Each segment is the plaintext chunk sealed with AES-256-GCM:

- **Key**: a per-file key. For passwords it is `PBKDF2-HMAC-SHA256(password, salt, iterations)`. For key files it is `HKDF-SHA256(key, salt, "aesf v1 file key")`. The random salt means every file gets its own key.
- **Nonce** (96 bits): `nonce prefix (7) || segment index (4, big-endian) || last-segment flag (1)`.
- **Associated data**: the entire header.

This is the segmented "online AEAD" construction used by Google Tink's streaming AEAD and similar to `age`. It gives these properties:

| Attack | Why it fails |
|---|---|
| Flip any bit in a segment | The GCM tag check fails. |
| Change the header (iterations, segment size, salt) | The header is authenticated as associated data in every segment, and the salt also changes the key. |
| Reorder or duplicate segments | The index is part of the nonce. |
| Truncate at a segment boundary | The new final segment was not sealed with the last-segment flag. |
| Append data | The real final segment is no longer last, so its flag no longer matches. |
| Splice segments between files | Each file has a different key. |

Each of these is covered by a unit test in `FileCryptoTest`.

### Threat model and limitations

- **The `reference` engine is not constant-time.** Its AES uses table lookups indexed by secret data, which can leak key bits through CPU cache timing to an attacker running code on the same machine. That is why the default engine is `jca`, which uses hardware AES and carry-less-multiply instructions (AES-NI/PCLMULQDQ, ARMv8 Crypto). The reference GHASH multiply itself is branch-free and table-free.
- **Password strength matters.** PBKDF2 slows guessing but cannot save a weak password. For high-value data, prefer a key file. A memory-hard KDF (Argon2/scrypt) would be stronger but requires a dependency; the format's KDF byte leaves room to add one.
- **Key wiping is best-effort.** Keys and passwords are zeroized after use, but the JVM may copy memory during garbage collection, and the JDK's `SecretKeySpec` cannot be wiped.
- **Decrypting to stdout can emit partial output before failing.** Each segment is authenticated before it is released, and the process exits with code `2`, but earlier segments have already been written to the pipe. Decrypting to a file is fully atomic.
- **Metadata is not hidden.** File size (to within a segment) and modification times remain visible.
- **Out of scope**: attackers who control the machine while you decrypt, keyloggers, and secure deletion of the original plaintext.

## Architecture

```
io.github.ak811.aes
├── core        BlockCipher interface, Aes (FIPS-197, from scratch)
├── mode        Ecb (demo/KATs only), Ctr (SP 800-38A)
├── aead        Aead interface, Gcm (SP 800-38D, from scratch), JcaAesGcm, Engine
├── kdf         Hkdf (RFC 5869), Pbkdf2 (RFC 8018)
├── format      FileHeader, FileCrypto (streaming AEAD), KeySource, KeyFiles, EncryptOptions
├── io          AtomicFileOutput (temp file + fsync + atomic rename)
├── selftest    TestVectors, KnownAnswerTests
├── demo        EcbLeakageDemo
├── cli         Cli, Args, Passwords, Main
└── util        Bytes
```

The layers depend only downward. `format` knows nothing about the CLI, so it can be used as a library:

```java
try (KeySource key = KeySource.rawKey(keyBytes);
     InputStream in = Files.newInputStream(source);
     OutputStream out = Files.newOutputStream(target)) {
    FileCrypto.encrypt(in, out, key, EncryptOptions.defaults());
}
```

### Implementation notes

- The AES S-box and the GF(2^8) multiplication tables are **computed at class load** from their definitions (multiplicative inverse followed by the affine transform) rather than pasted as constants.
- The key schedule, `ShiftRows`, `MixColumns` and their inverses follow FIPS-197 section 5 directly, with 128/192/256-bit keys (10/12/14 rounds).
- GCM computes and checks the tag **before** decrypting, so it never produces unauthenticated plaintext, and it compares tags in constant time.

## Testing

`mvn verify` runs 53 tests:

- **Known-answer tests**: FIPS-197 Appendix B and C.1 to C.3 (AES-128/192/256), NIST SP 800-38A ECB and CTR, the GCM specification test cases 1 to 4 and 16, RFC 5869 HKDF, and RFC 7914 PBKDF2.
- **Differential tests against the JDK**: 1,500 random AES blocks across all key sizes, CTR at every length from 0 to 199 bytes, and 1,500 random GCM encryptions (varying key size, AAD and length) that must match `AES/GCM/NoPadding` exactly in both directions.
- **Tamper tests**: every single-bit flip of a GCM ciphertext is rejected, plus the file-level truncation, append, reorder and splice attacks listed above.
- **CLI tests**: round trips through files and pipes, wrong passwords, overwrite protection, cleanup of temporary files, and error reporting.

CI runs the suite on Java 17 and 21, then runs `selftest` on the packaged jar.

## `ecb-demo`

```bash
aesf ecb-demo                 # uses a generated sample image
aesf ecb-demo photo.png -o out/
```

![Original, ECB-encrypted and CTR-encrypted image](docs/ecb-demo.png)

Left to right: the original, AES-ECB, and AES-CTR, all encrypted with the same key. ECB leaks every shape; CTR looks like noise. GCM, which this tool uses, is CTR plus authentication.

## License

MIT. See [LICENSE](LICENSE).
