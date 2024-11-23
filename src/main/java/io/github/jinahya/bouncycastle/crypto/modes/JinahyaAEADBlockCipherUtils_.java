package io.github.jinahya.bouncycastle.crypto.modes;

import _java.nio._ByteBufferUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.function.Function;
import java.util.function.IntConsumer;

@SuppressWarnings({
        "java:S101",  // Class names should comply with a naming convention
        "java:S106",  // Standard outputs should not be used directly to log anything
        "java:S107",  // Methods should not have too many parameters
        "java:S1874", // "@Deprecated" code should not be used
        "java:S4274"  // Asserts should not be used to check the parameters of a public method
})
final class JinahyaAEADBlockCipherUtils_ {

    static int processBytesAndDoFinal(final AEADBlockCipher cipher, final byte[] in, final int inoff, final int inlen,
                                      final byte[] out, int outoff)
            throws InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert inlen >= 0;
        assert (inoff + inlen) <= in.length;
        assert out != null;
        assert outoff >= 0;
        assert outoff <= out.length;
        // -------------------------------------------------------------------------------------------------------------
        var outlen = cipher.processBytes(in, inoff, inlen, out, outoff); // DataLengthException
        outoff += outlen;
        outlen += cipher.doFinal(out, outoff); // InvalidCipherTextException
        return outlen;
    }

    static int processBytesAndDoFinal(final AEADBlockCipher cipher, final ByteBuffer input, final ByteBuffer output)
            throws InvalidCipherTextException {
        assert cipher != null;
        assert input != null;
        assert output != null;
        // ---------------------------------------------------------------------------------- <in>, <inoff>, and <inlen>
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
        // ------------------------------------------------------------------------------------------ <out> and <outoff>
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[output.remaining()];
            outoff = 0;
        }
        // -------------------------------------------------------------------------------------- processBytesAndDoFinal
        final var outlen = processBytesAndDoFinal(cipher, in, inoff, inlen, out, outoff);
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        input.position(input.position() + inlen);
        return outlen;
    }

    static long processAllBytesAndDoFinal(final AEADBlockCipher cipher, final InputStream in, final OutputStream out,
                                          final byte[] inbuf, byte[] outbuf, final IntConsumer inconsumer,
                                          final Function<? super byte[], ? extends IntConsumer> outconsumer)
            throws IOException, InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert out != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        if (outbuf == null || outbuf.length == 0) {
            outbuf = new byte[1];
        }
        assert inconsumer != null;
        assert outconsumer != null;
        // -------------------------------------------------------------------------------------------------------------
        var bytes = 0L;
        // ------------------------------------------------------------------------------------------------ processBytes
        for (int r; (r = in.read(inbuf)) != -1; ) {
            for (final var l = cipher.getUpdateOutputSize(r); outbuf.length < l; ) {
                System.out.println("re-allocating outbuf(" + outbuf.length +
                                           ") for an intermediate update-output-size: " + l);
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[l];
            }
            final var outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0); // DataLengthException
            out.write(outbuf, 0, outlen);
            inconsumer.accept(r);
            outconsumer.apply(outbuf).accept(outlen);
            bytes += outlen;
        }
        // ----------------------------------------------------------------------------------------------------- doFinal
        for (final var l = cipher.getOutputSize(0); outbuf.length < l; ) {
            System.out.println("re-allocating outbuf(" + outbuf.length + ") for the final output-size: " + l);
            Arrays.fill(outbuf, (byte) 0);
            outbuf = new byte[l];
        }
        final var outlen = cipher.doFinal(outbuf, 0); // InvalidCipherTextException
        out.write(outbuf, 0, outlen);
        outconsumer.apply(outbuf).accept(outlen);
        bytes += outlen;
        // -------------------------------------------------------------------------------------------------------------
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
