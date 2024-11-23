package io.github.jinahya.bouncycastle.crypto;

import _java.nio._ByteBufferUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.function.Function;
import java.util.function.IntConsumer;

final class JinahyaBufferedBlockCipherUtils_ {

    static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] in, final int inoff,
                                      final int inlen, final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert inlen >= 0;
        assert inoff + inlen <= in.length;
        assert out != null;
        assert outoff >= 0;
        assert outoff <= out.length;
        // -------------------------------------------------------------------------------------------------------------
        var outlen = cipher.processBytes(in, inoff, inlen, out, outoff); // DataLengthException
        outlen += cipher.doFinal(out, outlen); // InvalidCipherTextException
        return outlen;
    }

    static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input, final ByteBuffer output)
            throws InvalidCipherTextException {
        assert cipher != null;
        assert input != null;
        assert output != null;
        // -------------------------------------------------------------------------------------------------------------
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
        // -------------------------------------------------------------------------------------------------------------
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[output.remaining()];
            outoff = 0;
        }
        // -------------------------------------------------------------------------------------------------------------
        final var outlen = processBytesAndDoFinal(cipher, in, inoff, inlen, out, outoff);
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        input.position(input.position() + inlen);
        return outlen;
    }

    static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream in,
                                          final OutputStream out, final byte[] inbuf, byte[] outbuf,
                                          final IntConsumer inconsumer,
                                          final Function<? super byte[], ? extends IntConsumer> outconsumer)
            throws IOException, InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert out != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        if (outbuf == null || outbuf.length == 0) {
            outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        }
        assert outbuf.length > 0;
        // -------------------------------------------------------------------------------------------------------------
        var bytes = 0L;
        int outlen;
        // -------------------------------------------------------------------------------------------------------------
        for (int r; (r = in.read(inbuf)) != -1; ) {
            for (final var uos = cipher.getUpdateOutputSize(r); outbuf.length < uos; ) {
                System.out.println(
                        "re-allocating outbuf(" + outbuf.length + ")" +
                                " for an intermediate update-output-size(" + uos + ")"
                );
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[uos];
            }
            outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
            out.write(outbuf, 0, outlen);
            inconsumer.accept(r);
            outconsumer.apply(outbuf).accept(outlen);
            bytes += outlen;
        }
        // -------------------------------------------------------------------------------------------------------------
        for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
            System.out.println(
                    "re-allocating outbuf(" + outbuf.length + ")" +
                            " for the final output-size(" + os + ")"
            );
            Arrays.fill(outbuf, (byte) 0);
            outbuf = new byte[os];
        }
        outlen = cipher.doFinal(outbuf, 0);
        out.write(outbuf, 0, outlen);
        outconsumer.apply(outbuf).accept(outlen);
        bytes += outlen;
        // -------------------------------------------------------------------------------------------------------------
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBufferedBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
