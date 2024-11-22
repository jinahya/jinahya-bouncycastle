package io.github.jinahya.bouncycastle.crypto;

import _java.nio._ByteBufferUtils;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;

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
        "java:S127",  // "for" loop stop conditions should be invariant
        "java:S1874", // "@Deprecated" code should not be used
        "java:S4274"  // Asserts should not be used to check the parameters of a public method
})
final class JinahyaStreamCipherUtils_ {

    static byte[] processBytes(final StreamCipher cipher, final byte[] in, final int inoff, final int inlen) {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert inoff <= in.length;
        assert inlen >= 0;
        assert (inoff + inlen) <= in.length;
        // -------------------------------------------------------------------------------------------------------------
        for (var out = new byte[in.length == 0 ? 1 : in.length]; ; ) {
            try {
                final var outlen = cipher.processBytes(in, inoff, inlen, out, 0);
                return Arrays.copyOf(out, outlen);
            } catch (final DataLengthException dle) {
                System.err.println("doubling up out.length(" + out.length + ")");
                out = new byte[out.length << 1];
            }
        }
    }

    static int processBytes(final StreamCipher cipher, final ByteBuffer input, final ByteBuffer output) {
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
        final var out = processBytes(cipher, in, inoff, inlen);
        output.put(out); // BufferOverflowException
        input.position(input.position() + inlen);
        return out.length;
    }

    // -----------------------------------------------------------------------------------------------------------------
    static long processAllBytes(final StreamCipher cipher, final InputStream in, final OutputStream out,
                                final byte[] inbuf, byte[] outbuf, final IntConsumer inconsumer,
                                final Function<? super byte[], ? extends IntConsumer> outconsumer)
            throws IOException {
        assert cipher != null;
        assert in != null;
        assert out != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        if (outbuf == null) {
            outbuf = new byte[inbuf.length << 1];
        }
        assert outbuf.length > 0;
        assert inconsumer != null;
        assert outconsumer != null;
        // -------------------------------------------------------------------------------------------------------------
        var bytes = 0L;
        for (int outlen, r; (r = in.read(inbuf)) != -1; ) {
            while (true) {
                try {
                    outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
                    out.write(outbuf, 0, outlen);
                    inconsumer.accept(r);
                    outconsumer.apply(outbuf).accept(outlen);
                    bytes += outlen;
                    break;
                } catch (final DataLengthException dle) {
                    System.err.println("doubling up outbuf.length(" + outbuf.length + ")");
                    Arrays.fill(outbuf, (byte) 0);
                    outbuf = new byte[outbuf.length << 1];
                }
            }
        }
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
