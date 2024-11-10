package io.github.jinahya.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * A utility class for {@link AEADCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaAEADCipherCrypto
 */
public final class JinahyaAEADCipherUtils {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Processes and finalizes, using specified cipher, bytes in specified range of specified input array, and set
     * processed bytes on specified output array starting at specified output position.
     *
     * @param cipher the cipher.
     * @param in     the input array.
     * @param inoff  the starting position of {@code in}.
     * @param inlen  the number of bytes to process.
     * @param out    the output array.
     * @param outoff the starting position of the {@code out}.
     * @return the number of processed bytes set on the {@code out}.
     * @throws DataLengthException        if the output array is too small.
     * @throws InvalidCipherTextException if the MAC fails to match.
     * @see AEADCipher#processBytes(byte[], int, int, byte[], int)
     * @see AEADCipher#doFinal(byte[], int)
     */
    public static int processBytesAndDoFinal(final AEADCipher cipher, final byte[] in, final int inoff, final int inlen,
                                             final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") is negative");
        }
        if (inlen < 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is negative");
        }
        if (inoff + inlen > in.length) {
            throw new IllegalArgumentException(
                    "inoff(" + inoff + ") + inlen(" + inlen + ") > in.length(" + in.length + ")");
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if (outoff > out.length) {
            throw new IllegalArgumentException("outoff(" + outoff + ") > out.length(" + out.length + ")");
        }
        var outlen = cipher.processBytes(in, inoff, inlen, out, outoff); // DataLengthException
        outlen += cipher.doFinal(out, outoff + outlen); // InvalidCipherTextException
        return outlen;
    }

    /**
     * Processes and finalizes, using specified cipher, all remaining bytes of specified input buffer, and put processed
     * bytes to specified output buffer.
     *
     * @param cipher the cipher.
     * @param input  the input buffer whose remaining bytes are processed.
     * @param output the output buffer onto which processed bytes are put.
     * @return the number of bytes put on the {@code output}.
     * @throws DataLengthException        if the output buffer is too small.
     * @throws InvalidCipherTextException if the MAC fails to match.
     * @see #processBytesAndDoFinal(AEADCipher, byte[], int, int, byte[], int)
     */
    public static int processBytesAndDoFinal(final AEADCipher cipher, final ByteBuffer input, final ByteBuffer output)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        final byte[] in;
        final int inoff;
        final int inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = new byte[inlen];
//            input.get(0, in); // Java 13
            for (int p = input.position(), i = 0; i < in.length; p++, i++) {
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
        final var outlen = processBytesAndDoFinal(cipher, in, inoff, inlen, out, outoff);
        input.position(input.position() + inlen);
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        return outlen;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static long processAllBytesAndDoFinal(final AEADCipher cipher, final InputStream in, final OutputStream out,
                                                 final byte[] inbuf, final int inoff, final int inlen, byte[] outbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") < 0");
        }
        if (inlen <= 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") <= 0");
        }
        if (inoff + inlen > inbuf.length) {
            throw new IllegalArgumentException(
                    "inoff(" + inoff + ") + inlen(" + inlen + ") > inbuf.length(" + inbuf.length + ")"
            );
        }
        if (outbuf == null || outbuf.length == 0) {
            outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        }
        var bytes = 0L;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            for (final var uos = cipher.getUpdateOutputSize(r); outbuf.length < uos; ) {
                System.err.println("re-allocating outbuf(" + outbuf.length +
                                           ") for an intermediate update output size: " + uos);
                Arrays.fill(outbuf, (byte) 0);
                outbuf = new byte[uos];
            }
            final var outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0); // DataLengthException
            out.write(outbuf, 0, outlen);
            bytes += outlen;
        }
        for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
            System.err.println("re-allocating outbuf(" + outbuf.length + ") for the final output size: " + os);
            Arrays.fill(outbuf, (byte) 0);
            outbuf = new byte[os];
        }
        final var outlen = cipher.doFinal(outbuf, 0); // InvalidCipherTextException
        out.write(outbuf, 0, outlen);
        bytes += outlen;
        Arrays.fill(outbuf, (byte) 0);
        return bytes;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
