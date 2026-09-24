package io.github.ak811.aes.io;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

/**
 * Writes a file so that it either appears complete or not at all.
 *
 * <p>Data goes to a hidden temporary file in the target's directory (created with owner-only
 * permissions on POSIX systems). {@link #commit()} flushes it to disk and renames it over the
 * target; closing without committing deletes it. This guarantees a failed decryption never leaves
 * partial plaintext behind and a crash never leaves a half-written ciphertext.
 */
public final class AtomicFileOutput implements AutoCloseable {

    private static final int BUFFER_SIZE = 64 * 1024;

    private final Path target;
    private final Path temp;
    private final boolean overwrite;
    private final FileChannel channel;
    private final OutputStream stream;
    private boolean committed;

    private AtomicFileOutput(Path target, Path temp, boolean overwrite) throws IOException {
        this.target = target;
        this.temp = temp;
        this.overwrite = overwrite;
        this.channel = FileChannel.open(temp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
        this.stream = new BufferedOutputStream(Channels.newOutputStream(channel), BUFFER_SIZE);
    }

    public static AtomicFileOutput create(Path target, boolean overwrite) throws IOException {
        Path absolute = target.toAbsolutePath().normalize();
        if (Files.isDirectory(absolute)) {
            throw new IOException(target + " is a directory");
        }
        if (!overwrite && Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new FileAlreadyExistsException(target.toString());
        }
        Path dir = absolute.getParent();
        Path temp = Files.createTempFile(dir, "." + absolute.getFileName() + ".", ".partial");
        try {
            return new AtomicFileOutput(absolute, temp, overwrite);
        } catch (IOException | RuntimeException e) {
            Files.deleteIfExists(temp);
            throw e;
        }
    }

    public OutputStream stream() {
        return stream;
    }

    /** Flushes to stable storage and moves the file into place. */
    public void commit() throws IOException {
        if (committed) {
            return;
        }
        stream.flush();
        channel.force(true);
        stream.close();
        try {
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            if (overwrite) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.move(temp, target);
            }
        }
        committed = true;
    }

    @Override
    public void close() throws IOException {
        if (!committed) {
            try {
                stream.close();
            } finally {
                Files.deleteIfExists(temp);
            }
        }
    }
}
