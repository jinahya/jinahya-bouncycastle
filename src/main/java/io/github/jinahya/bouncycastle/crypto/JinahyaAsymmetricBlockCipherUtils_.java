package io.github.jinahya.bouncycastle.crypto;

import _java.nio._ByteBufferUtils;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.IntFunction;

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
        assert block.length <= cipher.getOutputBlockSize();
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
            _ByteBufferUtils.get(input, input.position(), in);
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

    static long processAllBlocks(
            final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out,
            final byte[] inbuf, final byte[] outbuf,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> inconsumer,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> outconsumer)
            throws IOException, InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert in.markSupported();
        assert out != null;
        assert inbuf != null;
        assert outbuf != null;
        final var inputBlockSize = cipher.getInputBlockSize();
        assert inbuf.length >= inputBlockSize;
        final var outputBlockSize = cipher.getOutputBlockSize();
        assert outbuf.length >= outputBlockSize;
        assert inconsumer != null;
        assert outconsumer != null;
        var blocks = 0L;
        for (int r, outlen; true;
             blocks = Math.addExact(blocks, 1L)) {
            in.mark(inputBlockSize);
            r = in.readNBytes(inbuf, 0, inputBlockSize);
            if (r < inputBlockSize) {
                in.reset();
                break;
            }
            outlen = processBlock(cipher, inbuf, 0, r, outbuf, 0);
            assert outlen <= outputBlockSize;
            out.write(outbuf, 0, outlen);
            inconsumer.apply(inbuf).apply(0).accept(r);
            outconsumer.apply(outbuf).apply(0).accept(outlen);
        }
        return blocks;
    }

    // -----------------------------------------------------------------------------------------------------------------
    static long processAllBytes(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out,
                                final byte[] inbuf, final byte[] outbuf,
                                final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> inconsumer,
                                final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> outconsumer)
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
        // -------------------------------------------------------------------------------------------------------------
        final var blocks = processAllBlocks(cipher, in, out, inbuf, outbuf, inconsumer, outconsumer);
        var bytes = Math.multiplyExact(blocks, cipher.getOutputBlockSize());
        // process last remaining bytes
        final var inlen = in.readNBytes(inbuf, 0, inbuf.length);
        if (inlen > 0) {
            assert inlen < cipher.getInputBlockSize();
            final var outlen = processBlock(cipher, inbuf, 0, inlen, outbuf, 0);
            assert outlen <= cipher.getOutputBlockSize();
            out.write(outbuf, 0, outlen);
            inconsumer.apply(inbuf).apply(0).accept(inlen);
            outconsumer.apply(outbuf).apply(0).accept(outlen);
            bytes = Math.addExact(bytes, inlen);
        }
        assert in.read() == -1;
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAsymmetricBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
