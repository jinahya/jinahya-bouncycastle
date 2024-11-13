package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

final class JinahyaAsymmetricBlockCipherUtils_ {

    // -----------------------------------------------------------------------------------------------------------------
    private static boolean readBlock(final InputStream in, final byte[] inbuf, final int inoff, final int bytes)
            throws IOException {
        assert in != null;
        assert in.markSupported();
        assert inbuf != null;
        assert bytes > 0;
        in.mark(bytes);
        if ((in.readNBytes(inbuf, inoff, bytes)) < bytes) {
            in.reset();
            return false;
        }
        return true;
    }

    static boolean processBlock(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out)
            throws IOException, InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert in.markSupported();
        assert out != null;
        final var inbuf = new byte[cipher.getInputBlockSize()];
        if (!readBlock(in, inbuf, 0, inbuf.length)) {
            return false;
        }
        final var outbuf = cipher.processBlock(inbuf, 0, inbuf.length);
        out.write(outbuf);
        return true;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static int readBlocks(final AsymmetricBlockCipher cipher, final InputStream in, final byte[] inbuf)
            throws IOException {
        assert cipher != null;
        assert in != null;
        assert in.markSupported();
        assert inbuf != null;
        int count = 0;
        {
            final var inlen = cipher.getInputBlockSize();
            final int limit = inbuf.length / cipher.getInputBlockSize();
            for (var inoff = 0; count < limit; count++, inoff += inlen) {
                if (!readBlock(in, inbuf, inoff, inlen)) {
                    break;
                }
            }
        }
        return count;
    }

    static long processAllBlocks(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out,
                                 final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert in.markSupported();
        assert out != null;
        assert inbuf != null;
        assert inbuf.length >= cipher.getInputBlockSize();
        var count = 0L;
        int inoff;
        final var inlen = cipher.getInputBlockSize();
        for (int blocks; (blocks = readBlocks(cipher, in, inbuf)) > 0; ) {
            inoff = 0;
            for (int i = 0; i < blocks; i++) {
                final var outbuf = cipher.processBlock(inbuf, inoff, inlen);
                out.write(outbuf);
                inoff += inlen;
                count++;
            }
        }
        return count;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAsymmetricBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
