package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntConsumer;

/**
 * A utility class for {@link StreamCipher} interface.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/index.html?org/bouncycastle/crypto/StreamCipher.html">org.bouncycastle.crypto.StreamCipher</a>
 * (bcprov-jdk18on-javadoc)
 */
public final class JinahyaStreamCipherUtils {

    /**
     * Processes, using specified cipher, specified range of specified array, and returns the result.
     *
     * @param cipher the cipher which should be {@link StreamCipher#init(boolean, CipherParameters) initialized}.
     * @param in     the input array.
     * @param inoff  a starting index of {@code in}.
     * @param inlen  a number of bytes to process from the {@code inoff}.
     * @return an array of processed bytes.
     */
    public static byte[] processBytes(final StreamCipher cipher, final byte[] in, final int inoff, final int inlen) {
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
                    "(inoff(" + inoff + ") + inlen(" + inlen + ")) > in.length(" + in.length + ")"
            );
        }
        return JinahyaStreamCipherUtils_.processBytes(cipher, in, inoff, inlen);
    }

    /**
     * Process, using specified cipher, all remaining bytes of specified input buffer, and puts processed bytes to
     * specified output buffer.
     *
     * @param cipher the cipher which should be {@link StreamCipher#init(boolean, CipherParameters) initialized}.
     * @param input  the input buffer whose remaining bytes are processed.
     * @param output the output buffer on which processed bytes are put.
     * @return the number of byte put on the {@code output}.
     * @throws java.nio.BufferOverflowException when {@code output.remaining()} is not enough.
     */
    public static int processBytes(final StreamCipher cipher, final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        return JinahyaStreamCipherUtils_.processBytes(cipher, input, output);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Processes, using specified cipher, all bytes from specified input stream, and writes processed bytes to specified
     * output stream.
     * {@snippet lang = "java":
     * byte[] inbuf = new byte[1];
     * byte[] outbuf = new byte[1]; // may be null
     * processAllBytes(
     *         cipher,
     *         in,
     *         out,
     *         inbuf,
     *         outbuf,
     *         l -> {
     *             // consume unprocessed bytes read from <in>
     *             digest.update(inbuf, 0, l);
     *         },
     *         b -> l -> {
     *             // <b> is not necessarily same as the <outbuf>
     *             // consume processed bytes written to the <out>
     *             mac.update(b, 0, l);
     *         }
     * );
     *}
     *
     * @param cipher      the cipher which should be {@link StreamCipher#init(boolean, CipherParameters) initialized}.
     * @param in          the input stream from which unprocessed bytes are read.
     * @param out         the output stream to which processed bytes are written.
     * @param inbuf       a buffer for reading unprocessed bytes from the input stream.
     * @param outbuf      a buffer for processed bytes; may be {@code null}.
     * @param inconsumer  a consumer continuously accepts the number of bytes set on the {@code inbuf}.
     * @param outconsumer a function, continuously applies with an output buffer (not necessarily same as
     *                    {@code outbuf}), results a consumer accepts the number of bytes set on the output buffer.
     * @return the number of bytes written to the {@code out}.
     * @throws IOException if an I/O error occurs.
     */
    public static long processAllBytes(final StreamCipher cipher, final InputStream in, final OutputStream out,
                                       final byte[] inbuf, byte[] outbuf, final IntConsumer inconsumer,
                                       final Function<? super byte[], ? extends IntConsumer> outconsumer)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        if (outbuf != null && outbuf.length == 0) {
            throw new IllegalArgumentException("outbuf.length is zero");
        }
        return JinahyaStreamCipherUtils_.processAllBytes(cipher, in, out, inbuf, outbuf, inconsumer, outconsumer);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
