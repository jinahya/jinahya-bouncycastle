package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.MultiBlockCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;
import java.util.function.IntConsumer;

/**
 * Utilities for {@link MultiBlockCipher} interface.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaMultiBlockCipherUtils {

    public static int processBlock(final MultiBlockCipher cipher, final byte[] in, final int inoff, final byte[] out,
                                   final int outoff) {
        return JinahyaBlockCipherUtils.processBlock(cipher, in, inoff, out, outoff);
    }

    public static long processAllBlocks(final MultiBlockCipher cipher, final InputStream in, final OutputStream out,
                                        final byte[] inbuf, byte[] outbuf, final IntConsumer inlenconsumer,
                                        final IntConsumer outlenconsumer)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        final var blockSize = cipher.getBlockSize();
        if (!Objects.requireNonNull(in, "in is null").markSupported()) {
            throw new IllegalArgumentException("in doesn't support mark");
        }
        Objects.requireNonNull(out, "out is null");
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
        Objects.requireNonNull(inlenconsumer, "inlenconsumer is null");
        Objects.requireNonNull(outlenconsumer, "outlenconsumer is null");
        // -------------------------------------------------------------------------------------------------------------
        return JinahyaMultiBlockCipherUtils_.processAllBlocks(
                cipher,
                in,
                out,
                inbuf,
                outbuf,
                inlenconsumer,
                outlenconsumer
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaMultiBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
