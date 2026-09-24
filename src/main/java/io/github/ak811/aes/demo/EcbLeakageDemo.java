package io.github.ak811.aes.demo;

import io.github.ak811.aes.core.Aes;
import io.github.ak811.aes.mode.Ctr;
import io.github.ak811.aes.mode.Ecb;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Polygon;
import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.imageio.ImageIO;

/**
 * Encrypts an image's raw pixels with ECB and with CTR under the same random key and saves both as
 * PNGs. With ECB, equal pixel runs become equal ciphertext blocks, so shapes remain clearly
 * visible; with CTR the output is indistinguishable from noise. This is the classic reason the
 * original version of this project (AES/ECB) was insecure.
 */
public final class EcbLeakageDemo {

    private EcbLeakageDemo() {
    }

    /**
     * @param image  an image to encrypt, or {@code null} to use a generated sample
     * @param outDir directory for the output PNGs
     * @return the files written
     */
    public static List<Path> run(Path image, Path outDir) throws IOException {
        System.setProperty("java.awt.headless", "true");
        Files.createDirectories(outDir);
        List<Path> written = new ArrayList<>();

        BufferedImage source;
        String stem;
        if (image == null) {
            source = sampleImage();
            stem = "sample";
            written.add(write(source, outDir.resolve(stem + ".png")));
        } else {
            source = ImageIO.read(image.toFile());
            if (source == null) {
                throw new IOException("unsupported image format: " + image);
            }
            String name = image.getFileName().toString();
            int dot = name.lastIndexOf('.');
            stem = dot > 0 ? name.substring(0, dot) : name;
        }

        int width = source.getWidth();
        int height = source.getHeight();
        byte[] pixels = pixels(toBgr(source));

        SecureRandom random = new SecureRandom();
        byte[] key = new byte[32];
        byte[] iv = new byte[16];
        random.nextBytes(key);
        random.nextBytes(iv);

        byte[] ecb = pixels.clone();
        byte[] ctr;
        try (Aes aes = new Aes(key)) {
            int whole = pixels.length - pixels.length % 16;
            byte[] blocks = Ecb.encrypt(aes, Arrays.copyOf(pixels, whole));
            System.arraycopy(blocks, 0, ecb, 0, whole);
            ctr = Ctr.apply(aes, iv, pixels);
        }

        written.add(write(fromBgr(width, height, ecb), outDir.resolve(stem + "-ecb.png")));
        written.add(write(fromBgr(width, height, ctr), outDir.resolve(stem + "-ctr.png")));
        return written;
    }

    /** Flat-colour shapes: the worst case for ECB and therefore the clearest demonstration. */
    private static BufferedImage sampleImage() {
        BufferedImage img = new BufferedImage(480, 320, BufferedImage.TYPE_3BYTE_BGR);
        Graphics2D g = img.createGraphics();
        g.setColor(new Color(0xF4F1E8));
        g.fillRect(0, 0, 480, 320);
        g.setColor(new Color(0x1F4E79));
        g.fillOval(30, 50, 200, 200);
        g.setColor(new Color(0xC0392B));
        g.fillRect(260, 40, 180, 110);
        g.setColor(new Color(0x27AE60));
        g.fillPolygon(new Polygon(new int[] {270, 440, 355}, new int[] {290, 290, 170}, 3));
        g.dispose();
        return img;
    }

    private static BufferedImage toBgr(BufferedImage src) {
        BufferedImage bgr = new BufferedImage(src.getWidth(), src.getHeight(), BufferedImage.TYPE_3BYTE_BGR);
        Graphics2D g = bgr.createGraphics();
        g.drawImage(src, 0, 0, null);
        g.dispose();
        return bgr;
    }

    private static byte[] pixels(BufferedImage bgr) {
        return ((DataBufferByte) bgr.getRaster().getDataBuffer()).getData().clone();
    }

    private static BufferedImage fromBgr(int width, int height, byte[] data) {
        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_3BYTE_BGR);
        byte[] target = ((DataBufferByte) img.getRaster().getDataBuffer()).getData();
        System.arraycopy(data, 0, target, 0, target.length);
        return img;
    }

    private static Path write(BufferedImage img, Path path) throws IOException {
        if (!ImageIO.write(img, "png", path.toFile())) {
            throw new IOException("no PNG writer available");
        }
        return path;
    }
}
