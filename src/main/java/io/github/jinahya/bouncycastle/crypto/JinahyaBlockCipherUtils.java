package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntConsumer;

/**
 * A utility class for {@link BlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/BlockCipher.html">org.bouncycastle.crypto.BlockCipher</a>
 * (bcprov-jdk18on-javadoc)
 */
public final class JinahyaBlockCipherUtils {

    /**
     * Processes, using specified cipher, an unprocessed block bytes in specified input array starting from specified
     * input index, and set processed block bytes to specified output array starting at specified output index.
     *
     * @param cipher the cipher.
     * @param in     the input array.
     * @param inoff  the starting index of {@code in}.
     * @param out    the output array on which processed bytes are set.
     * @param outoff the starting index of {@code out}.
     * @return the number of bytes set on the {@code out}.
     */
    public static int processBlock(final BlockCipher cipher, final byte[] in, final int inoff, final byte[] out,
                                   final int outoff) {
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
        return JinahyaBlockCipherUtils_.processBlock(
                cipher,
                in,
                inoff,
                out,
                outoff
        );
    }

    public static long processAllBlocks(final BlockCipher cipher, final InputStream in, final OutputStream out,
                                        final byte[] inbuf, final byte[] outbuf,
                                        final Function<? super byte[], ? extends IntConsumer> inconsumer,
                                        final Function<? super byte[], ? extends IntConsumer> outconsumer)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        if (!Objects.requireNonNull(in, "in is null").markSupported()) {
            throw new IllegalArgumentException("in doesn't support mark");
        }
        Objects.requireNonNull(out, "out is null");
        final var blockSize = cipher.getBlockSize();
        if (Objects.requireNonNull(inbuf, "inbuf is null").length < blockSize) {
            throw new IllegalArgumentException(
                    "inbuf.length(" + inbuf.length + ") < cipher.blockSize(" + blockSize + ")"
            );
        }
        if (Objects.requireNonNull(outbuf, "outbuf is null").length < blockSize) {
            throw new IllegalArgumentException(
                    "outbuf.length(" + outbuf.length + ") < cipher.blockSize(" + blockSize + ")"
            );
        }
        Objects.requireNonNull(inconsumer, "inconsumer is null");
        Objects.requireNonNull(outconsumer, "outconsumer is null");
        return JinahyaBlockCipherUtils_.processAllBlocks(
                cipher,
                in,
                out,
                inbuf,
                outbuf,
                inconsumer,
                outconsumer
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
