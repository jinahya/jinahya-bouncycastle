package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

final class JinahyaAsymmetricBlockCipherUtils_ {

    static long processAllBlocks(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out)
            throws IOException, InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert in.markSupported();
        assert out != null;
        final var inbuf = new byte[cipher.getInputBlockSize()];
        for (var c = 0L; ; c++) {
            in.mark(inbuf.length);
            if (in.readNBytes(inbuf, 0, inbuf.length) < inbuf.length) {
                in.reset();
                return c;
            }
            final var outbuf = cipher.processBlock(inbuf, 0, inbuf.length); // DataLengthException
            out.write(outbuf);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAsymmetricBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
