package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * A utility class for {@link BlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/BlockCipher.html">org.bouncycastle.crypto.BlockCipher</a>
 * (bcprov-jdk18on-javadoc)
 */
public final class JinahyaBlockCipherUtils {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Processes, using specified cipher, a block bytes from specified input array, and set processed bytes on specified
     * output array.
     *
     * @param cipher the cipher.
     * @param in     the input array to process.
     * @param inoff  a starting index of the {@code in}.
     * @param out    the output array.
     * @param outoff a starting index of the {@code out}.
     * @param inmac  a mac to be updated with unprocessed bytes; may be {@code null}.
     * @param outmac a mac to be updated with processed bytes; may be {@code null}.
     * @return the number of bytes set on the output array.
     * @see BlockCipher#processBlock(byte[], int, byte[], int)
     */
    public static int processBlock(final BlockCipher cipher, final byte[] in, final int inoff, final byte[] out,
                                   final int outoff, final Mac inmac, final Mac outmac) {
        Objects.requireNonNull(cipher, "cipher is null");
        final var blockSize = cipher.getBlockSize();
        Objects.requireNonNull(in, "in is null");
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") is negative");
        }
        if ((in.length - inoff) < blockSize) {
            throw new IllegalArgumentException(
                    "in.length(" + in.length + ") - inoff(" + inoff + ") > cipher.blockSize(" + blockSize + ")"
            );
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if ((out.length - outoff) < blockSize) {
            throw new IllegalArgumentException(
                    "out.length(" + out.length + ") - outoff(" + outoff + ") > cipher.blockSize(" + blockSize + ")"
            );
        }
        return JinahyaBlockCipherUtils_.processBlock(cipher, in, inoff, out, outoff, inmac, outmac);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static boolean readBlock(final InputStream in, final byte[] inbuf, int inoff, final int blockSize)
            throws IOException {
        in.mark(blockSize);
        for (int remaining = blockSize, r; remaining > 0; inoff += r, remaining -= r) {
            if ((r = in.read(inbuf, inoff, remaining)) == -1) {
                in.reset();
                return false;
            }
        }
        return true;
    }

    public static int readBlocks(final InputStream in, final byte[] inbuf, final int bytes)
            throws IOException {
        int blocks = 0;
        var inoff = 0;
        final int limit = inbuf.length - blocks;
        for (; inoff < limit; inoff += bytes) {
            if (readBlock(in, inbuf, inoff, bytes)) {
                blocks++;
                continue;
            }
            break;
        }
        return blocks;
    }

    private static void processBlocks(final BlockCipher cipher, final OutputStream out, final byte[] inbuf,
                                      final byte[] outbuf, final int bytes, final int count)
            throws IOException {
        for (int i = 0, inoff = 0, outlen; i < count; i++, inoff += bytes) {
            outlen = cipher.processBlock(inbuf, inoff, outbuf, 0);
            assert outlen == bytes;
            out.write(outbuf, 0, outlen);
        }
    }

    /**
     * Processes all blocks, using specified cipher, from specified input stream, and write processed blocks to
     * specified output stream.
     *
     * @param cipher the cipher.
     * @param in     the input stream from which blocks are read.
     * @param out    tht output stream to which processed blocks are written.
     * @param inbuf  a buffer for reading blocks from {@code in}.
     * @param outbuf a buffer for processed blocks.
     * @return the number of processed blocks.
     * @throws IOException if an I/O error occurs.
     */
    public static long processAllBlocks(final BlockCipher cipher, final InputStream in, final OutputStream out,
                                        final byte[] inbuf, final byte[] outbuf)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        if (!Objects.requireNonNull(in, "in is null").markSupported()) {
            throw new IllegalArgumentException("in doesn't support mark");
        }
        Objects.requireNonNull(out, "out is null");
        final var bytes = cipher.getBlockSize();
        if (Objects.requireNonNull(inbuf, "inbuf is null").length < bytes) {
            throw new IllegalArgumentException(
                    "inbuf.length(" + inbuf.length + ") < cipher.blockSize(" + bytes + ")"
            );
        }
        if (Objects.requireNonNull(outbuf, "outbuf is null").length < inbuf.length) {
            throw new IllegalArgumentException(
                    "outbuf.length(" + outbuf.length + ") < inbuf.length(" + inbuf.length + ")"
            );
        }
        var count = 0L;
        for (int c; (c = readBlocks(in, inbuf, bytes)) > 0; ) {
            processBlocks(cipher, out, inbuf, outbuf, bytes, c);
            count += c;
        }
        return count;
    }

    /**
     * Processes, using specified cipher, all blocks from specified input stream, and write processed blocks to
     * specified output stream.
     *
     * @param cipher the cipher.
     * @param in     the input stream from which unprocessed blocks are read.
     * @param out    the output stream to which processed blocks are written.
     * @return the number of blocks processed.
     * @throws IOException if an I/O error occurs.
     */
    public static long processAllBlocks(final BlockCipher cipher, final InputStream in, final OutputStream out)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        if (!Objects.requireNonNull(in, "in is null").markSupported()) {
            throw new IllegalArgumentException("in doesn't support mark");
        }
        Objects.requireNonNull(out, "out is null");
        return JinahyaBlockCipherUtils_.processAllBlocks(cipher, in, out);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
