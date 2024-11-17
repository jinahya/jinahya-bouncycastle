package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

final class JinahyaBlockCipherUtils_ {

    /**
     * @param cipher
     * @param in
     * @param inoff
     * @param out
     * @param outoff
     * @param mac
     * @return
     * @see BlockCipher#processBlock(byte[], int, byte[], int)
     */
    static int processBlock(final BlockCipher cipher, final byte[] in, final int inoff, final byte[] out,
                            final int outoff, final Mac mac) {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert out != null;
        assert outoff >= 0;
        final var outlen = cipher.processBlock(in, inoff, out, outoff);
        final var blockSize = cipher.getBlockSize();
        assert outlen == blockSize;
        if (mac != null) {
            mac.update(in, inoff, blockSize);
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
