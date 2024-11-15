package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

final class JinahyaAsymmetricBlockCipherUtils_ {

    // -----------------------------------------------------------------------------------------------------------------
    static int processBlock(final AsymmetricBlockCipher cipher, final byte[] in, final int inoff,
                            final int inlen, final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert inlen >= 0;
        assert inlen <= cipher.getInputBlockSize();
        assert (inoff + inlen) <= in.length;
        assert out != null;
        assert outoff >= 0;
        assert (out.length - outoff) >= cipher.getOutputBlockSize();
        final var block = cipher.processBlock(in, inoff, inlen); // InvalidCipherTextException, DataLengthException
        System.arraycopy(block, 0, out, outoff, block.length); // IndexOutOfBoundsException
        return block.length;
    }

    static int processBlock(final AsymmetricBlockCipher cipher, final ByteBuffer input, final ByteBuffer output)
            throws InvalidCipherTextException {
        assert cipher != null;
        assert input != null;
        assert input.remaining() <= cipher.getInputBlockSize();
        assert output != null;
        assert output.remaining() >= cipher.getOutputBlockSize();
        final byte[] in;
        final int inoff;
        final int inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = new byte[inlen];
            for (int i = 0, p = input.position(); i < in.length; i++, p++) {
                in[i] = input.get(p);
            }
            inoff = 0;
        }
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[output.remaining()];
            outoff = 0;
        }
        final var outlen = processBlock(cipher, in, inoff, inlen, out, outoff);
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        input.position(input.position() + inlen);
        return outlen;
    }

    // -----------------------------------------------------------------------------------------------------------------
    static long processAllBytes(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out,
                                final byte[] inbuf, final byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert out != null;
        assert inbuf != null;
        assert outbuf != null;
        final var inputBlockSize = cipher.getInputBlockSize();
        assert inbuf.length >= inputBlockSize;
        final var outputBlockSize = cipher.getOutputBlockSize();
        assert outbuf.length >= outputBlockSize;
        var bytes = 0L;
        for (int r, outlen; (r = in.readNBytes(inbuf, 0, inputBlockSize)) > 0; ) {
            outlen = processBlock(cipher, inbuf, 0, r, outbuf, 0);
            out.write(outbuf, 0, outlen);
            bytes += outlen;
        }
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    static long x(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out,
                  final byte[] inbuf, final byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert out != null;
        assert inbuf != null;
        assert outbuf != null;
        final var inputBlockSize = cipher.getInputBlockSize();
        assert inbuf.length >= inputBlockSize;
        final var outputBlockSize = cipher.getOutputBlockSize();
        assert outbuf.length >= outputBlockSize;
        var bytes = 0L;
        for (int r, outlen; (r = in.readNBytes(inbuf, 0, inputBlockSize)) > 0; ) {
            outlen = processBlock(cipher, inbuf, 0, r, outbuf, 0);
            out.write(outbuf, 0, outlen);
            bytes += outlen;
        }
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAsymmetricBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
