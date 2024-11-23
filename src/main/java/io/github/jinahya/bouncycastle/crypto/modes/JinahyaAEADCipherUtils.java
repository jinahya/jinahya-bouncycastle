package io.github.jinahya.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntConsumer;

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
        if ((inoff + inlen) > in.length) {
            throw new IllegalArgumentException(
                    "(inoff(" + inoff + ") + inlen(" + inlen + ")) > in.length(" + in.length + ")");
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if (outoff > out.length) {
            throw new IllegalArgumentException("outoff(" + outoff + ") > out.length(" + out.length + ")");
        }
        return JinahyaAEADCipherUtils_.processBytesAndDoFinal(cipher, in, inoff, inlen, out, outoff);
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
        return JinahyaAEADCipherUtils_.processBytesAndDoFinal(cipher, input, output);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static long processAllBytesAndDoFinal(final AEADCipher cipher, final InputStream in, final OutputStream out,
                                                 final byte[] inbuf, byte[] outbuf, final IntConsumer inconsumer,
                                                 final Function<? super byte[], ? extends IntConsumer> outconsumer)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        if (outbuf == null) {
            outbuf = new byte[Math.max(1, cipher.getOutputSize(inbuf.length))];
        }
        if (outbuf.length == 0) {
            throw new IllegalArgumentException("outbuf.length(" + outbuf.length + ") is zero");
        }
        return JinahyaAEADCipherUtils_.processAllBytesAndDoFinal(
                cipher, in, out, inbuf, outbuf, inconsumer, outconsumer);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
