package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

final class JinahyaBlockCipherUtils_ {

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
    static int processBlock(final BlockCipher cipher, final byte[] in, final int inoff, final byte[] out,
                            final int outoff, final Mac inmac, final Mac outmac) {
        assert cipher != null;
        final var blockSize = cipher.getBlockSize();
        assert in != null;
        assert inoff >= 0;
        assert (in.length - inoff) >= blockSize;
        assert out != null;
        assert outoff >= 0;
        assert (out.length - outoff) >= blockSize;
        final var outlen = cipher.processBlock(in, inoff, out, outoff);
        assert outlen == blockSize;
        if (inmac != null) {
            inmac.update(in, inoff, blockSize);
        }
        if (outmac != null) {
            outmac.update(out, outoff, outlen);
        }
        return outlen;
    }

    static long processAllBlocks(final BlockCipher cipher, final InputStream in, final OutputStream out)
            throws IOException {
        assert cipher != null;
        assert in != null;
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
            final var bytes = cipher.processBlock(inbuf, 0, outbuf, 0); // DataLengthException
            assert bytes == outbuf.length;
            out.write(outbuf);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
