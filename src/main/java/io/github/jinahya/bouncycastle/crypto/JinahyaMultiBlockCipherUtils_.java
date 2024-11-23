package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.MultiBlockCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.IntConsumer;

final class JinahyaMultiBlockCipherUtils_ {

    static int processBlock(final MultiBlockCipher cipher, final byte[] in, final int inoff, final byte[] out,
                            final int outoff) {
        assert cipher != null;
        return JinahyaBlockCipherUtils_.processBlock(cipher, in, inoff, out, outoff);
    }

    static long processAllBlocks(final MultiBlockCipher cipher, final InputStream in, final OutputStream out,
                                 final byte[] inbuf, final byte[] outbuf, final IntConsumer inlenconsumer,
                                 final IntConsumer outlenconsumer)
            throws IOException {
        assert cipher != null;
        final var blockSize = cipher.getBlockSize();
        assert in != null;
        assert in.markSupported();
        assert out != null;
        assert inbuf != null;
        assert inbuf.length >= blockSize;
        assert outbuf != null;
        assert outbuf.length >= blockSize;
        assert inlenconsumer != null;
        assert outlenconsumer != null;
        // -------------------------------------------------------------------------------------------------------------
        var blocks = 0L;
        final var limit = Math.min(inbuf.length / blockSize, outbuf.length / blockSize);
        for (int count, inoff; ; ) {
            for (count = 0, inoff = 0; count < limit; count++, inoff += blockSize) {
                in.mark(blockSize);
                if (in.readNBytes(inbuf, inoff, blockSize) < blockSize) {
                    in.reset();
                    break;
                }
            }
            if (count == 0) {
                break;
            }
            final var outlen = cipher.processBlocks(inbuf, 0, count, outbuf, 0);
            out.write(outbuf, 0, outlen);
            inlenconsumer.accept(inoff);
            outlenconsumer.accept(outlen);
            blocks += count;
        }
        return blocks;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaMultiBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
