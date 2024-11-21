package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.IntFunction;

final class JinahyaBlockCipherUtils_ {

    private static int processBlock(final BlockCipher cipher, final int blockSize,
                                    final byte[] in, final int inoff,
                                    final byte[] out, final int outoff) {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert (in.length - inoff) >= blockSize;
        assert out != null;
        assert outoff >= 0;
        assert (out.length - outoff) >= blockSize;
        // -------------------------------------------------------------------------------------------------------------
        final var outlen = cipher.processBlock(in, inoff, out, outoff);
        assert outlen == blockSize;
        return outlen;
    }

    static int processBlock(final BlockCipher cipher,
                            final byte[] in, final int inoff,
                            final byte[] out, final int outoff) {
        assert cipher != null;
        return processBlock(
                cipher,
                cipher.getBlockSize(),
                in,
                inoff,
                out,
                outoff
        );
    }

    static long processAllBlocks(
            final BlockCipher cipher,
            final InputStream in, final OutputStream out,
            final byte[] inbuf, final byte[] outbuf,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> inconsumer,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> outconsumer)
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
        assert inconsumer != null;
        assert outconsumer != null;
        // -------------------------------------------------------------------------------------------------------------
        var blocks = 0L;
        for (int outlen; ; blocks++) {
            in.mark(blockSize);
            if (in.readNBytes(inbuf, 0, blockSize) < blockSize) {
                in.reset();
                break;
            }
            outlen = processBlock(
                    cipher,
                    blockSize,
                    inbuf,
                    0,
                    outbuf,
                    0
            );
            assert outlen == blockSize;
            out.write(outbuf, 0, outlen);
            inconsumer.apply(inbuf).apply(0).accept(blockSize);
            outconsumer.apply(outbuf).apply(0).accept(outlen);
        }
        return blocks;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
