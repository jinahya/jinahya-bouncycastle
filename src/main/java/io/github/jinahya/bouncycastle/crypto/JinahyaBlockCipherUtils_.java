package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.IntFunction;

final class JinahyaBlockCipherUtils_ {

    private static int processBlock(
            final BlockCipher cipher, final int blockSize,
            final byte[] in, final int inoff,
            final byte[] out, final int outoff,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> inconsumer,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> outconsumer) {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert (in.length - inoff) >= blockSize;
        assert out != null;
        assert outoff >= 0;
        assert (out.length - outoff) >= blockSize;
        assert inconsumer != null;
        assert outconsumer != null;
        // -------------------------------------------------------------------------------------------------------------
        final var outlen = cipher.processBlock(in, inoff, out, outoff);
        assert outlen == blockSize;
        inconsumer.apply(in).apply(0).accept(blockSize);
        outconsumer.apply(out).apply(0).accept(outlen);
        return outlen;
    }

    static int processBlock(
            final BlockCipher cipher,
            final byte[] in, final int inoff,
            final byte[] out, final int outoff,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> inconsumer,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> outconsumer) {

        assert cipher != null;
        return processBlock(
                cipher,
                cipher.getBlockSize(),
                in,
                inoff,
                out,
                outoff,
                inconsumer,
                outconsumer
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
                    0,
                    inconsumer,
                    outconsumer
            );
            assert outlen == blockSize;
            out.write(outbuf, 0, outlen);
        }
        return blocks;
    }

    static int processBlock(final BlockCipher cipher, final byte[] in, final int inoff, final byte[] out,
                            final int outoff, final Mac inmac, final Mac outmac) {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert (in.length - inoff) >= cipher.getBlockSize();
        assert out != null;
        assert outoff >= 0;
        assert (out.length - outoff) >= cipher.getBlockSize();
        final var outlen = cipher.processBlock(in, inoff, out, outoff);
        assert outlen == cipher.getBlockSize();
        if (inmac != null) {
            inmac.update(in, inoff, cipher.getBlockSize());
        }
        if (outmac != null) {
            outmac.update(out, outoff, outlen);
        }
        return outlen;
    }

//    static long processAllBlocks(final BlockCipher cipher, final InputStream in, final OutputStream out,
//                                 final byte[] inbuf, final byte[] outbuf, final Mac inmac, final Mac outmac)
//            throws IOException {
//        assert cipher != null;
//        assert in != null;
//        assert in.markSupported();
//        assert out != null;
//        assert inbuf != null;
//        assert outbuf != null;
//        final var blockSize = cipher.getBlockSize();
//        assert inbuf.length >= blockSize;
//        assert outbuf.length >= blockSize;
//        long blocks = 0L;
//        for (int outlen; ; blocks = Math.addExact(blocks, 1L)) {
//            in.mark(blockSize);
//            if (in.readNBytes(inbuf, 0, blockSize) < blockSize) {
//                in.reset();
//                break;
//            }
//            outlen = processBlock(cipher, inbuf, 0, outbuf, 0, inmac, outmac);
//            assert outlen == outbuf.length;
//            out.write(outbuf, 0, outlen);
//        }
//        return blocks;
//    }

    /**
     * Process, using specified cipher, all blocks from specified input stream, and writes processed blocks to specified
     * output stream.
     *
     * @param cipher the cipher.
     * @param in     the input stream from which unprocessed blocks are read.
     * @param out    the output stream to which processed blocks are written.
     * @return the number of blocks processed.
     * @throws IOException if an I/O error occurs.
     */
    static long processAllBlocks(final BlockCipher cipher, final InputStream in, final OutputStream out)
            throws IOException {
        assert cipher != null;
        assert in != null;
        assert in.markSupported();
        assert out != null;
        final var blockSize = cipher.getBlockSize();
        final var inbuf = new byte[blockSize];
        final var outbuf = new byte[inbuf.length];
        for (var c = 0L; ; c++) {
            in.mark(blockSize);
            if (in.readNBytes(inbuf, 0, inbuf.length) < inbuf.length) {
                in.reset();
                return c;
            }
            final var outlen = processBlock(cipher, inbuf, 0, outbuf, 0, (Mac) null, (Mac) null);
            assert outlen == outbuf.length;
            out.write(outbuf, 0, outlen);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
