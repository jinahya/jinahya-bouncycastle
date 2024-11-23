package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntConsumer;

/**
 * A utility class for {@link BufferedBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaBufferedBlockCipherCrypto
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/BufferedBlockCipher.html">org.bouncycastle.crypto.BufferedBlockCipher</a>
 * (bcprov-jdk18on-javadoc)
 * @see JinahyaBlockCipherUtils
 */
public final class JinahyaBufferedBlockCipherUtils {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Processes and finalizes, using specified cipher, bytes in specified range of specified input array, and set
     * processed bytes to specified output array starting at specified index.
     *
     * @param cipher the cipher.
     * @param in     the input array.
     * @param inoff  a starting index of {@code in}.
     * @param inlen  number of bytes to process in {@code in}.
     * @param out    the output array.
     * @param outoff the starting index of {@code out} on which processed bytes are set.
     * @return the number of bytes set on the {@code out}.
     * @throws DataLengthException        if there isn't enough space in {@code out}.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see BufferedBlockCipher#doFinal(byte[], int)
     */
    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final byte[] in, final int inoff,
                                             final int inlen, final byte[] out, final int outoff)
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
//        final var outputSize = cipher.getOutputSize(inlen);
//        if ((out.length - outoff) < outputSize) {
//            throw new IllegalArgumentException(
//                    "(out.length(" + out.length + ") - outoff(" + outoff + "))" +
//                            " < cipher.outputSize(inlen(" + inlen + "))(" + outputSize + ")");
//        }
        return JinahyaBufferedBlockCipherUtils_.processBytesAndDoFinal(cipher, in, inoff, inlen, out, outoff);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Processes and finalizes, using specified cipher, all remaining bytes of specified input buffer, and put process
     * bytes to specified output buffer.
     *
     * @param cipher the cipher.
     * @param input  the input buffer whose remaining bytes are processed.
     * @param output the output buffer onto which processed bytes are put.
     * @return the number of bytes put on the output buffer.
     * @throws DataLengthException        if there isn't enough space in {@code out}.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see #processBytesAndDoFinal(BufferedBlockCipher, byte[], int, int, byte[], int)
     */
    public static int processBytesAndDoFinal(final BufferedBlockCipher cipher, final ByteBuffer input,
                                             final ByteBuffer output)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        return JinahyaBufferedBlockCipherUtils_.processBytesAndDoFinal(cipher, input, output);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Processes and finalizes, using specified cipher, all bytes from specified input stream, and writes processed
     * bytes to specified output stream.
     *
     * @param cipher      the cipher.
     * @param in          the input stream from which unprocessed bytes are read.
     * @param out         the output stream to which processed bytes are written.
     * @param inbuf       a buffer for reading bytes from the input stream.
     * @param outbuf      a buffer for processed bytes.
     * @param inconsumer  a function applies with an input array results an int consumer accepts the number of bytes.
     * @param outconsumer a function applies with an output array results an int consumer accepts the number of bytes.
     * @return the number of bytes written to the {@code out}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException if padding is expected and not found.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see BufferedBlockCipher#doFinal(byte[], int)
     */
    public static long processAllBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream in,
                                                 final OutputStream out, final byte[] inbuf, final byte[] outbuf,
                                                 final IntConsumer inconsumer,
                                                 final Function<? super byte[], ? extends IntConsumer> outconsumer)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        Objects.requireNonNull(inconsumer, "inconsumer is null");
        Objects.requireNonNull(outconsumer, "outconsumer is null");
        return JinahyaBufferedBlockCipherUtils_.processAllBytesAndDoFinal(
                cipher,
                in,
                out,
                inbuf,
                outbuf,
                inconsumer,
                outconsumer
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
