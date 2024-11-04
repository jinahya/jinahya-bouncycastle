package io.github.jinahya.util.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;

/**
 * A utility class for {@link StreamCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/index.html?org/bouncycastle/crypto/StreamCipher.html">org.bouncycastle.crypto.StreamCipher</a>
 * (bcprov-jdk18on-javadoc)
 */
public final class JinahyaStreamCipherUtils {

    /**
     * Initializes specified cipher, with specified cipher parameters, for encryption, and returns the cipher.
     *
     * @param cipher the cipher to be initialized for encryption.
     * @param params the cipher parameters.
     * @param <T>    cipher type parameter
     * @return given {@code cipher}.
     * @see StreamCipher#init(boolean, CipherParameters)
     */
    public static <T extends StreamCipher> T initForEncryption(final T cipher, final CipherParameters params) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        cipher.init(true, params);
        return cipher;
    }

    /**
     * Initializes specified cipher, with specified cipher parameters, for decryption, and returns the cipher.
     *
     * @param cipher the cipher to be initialized for decryption.
     * @param params the cipher parameters.
     * @param <T>    cipher type parameter
     * @return given {@code cipher}.
     * @see StreamCipher#init(boolean, CipherParameters)
     */
    public static <T extends StreamCipher> T initForDecryption(final T cipher, final CipherParameters params) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        cipher.init(false, params);
        return cipher;
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Processes, using specified cipher, specified input bytes, and returns the result.
     *
     * @param cipher the cipher.
     * @param input  the input bytes to process.
     * @return an array of processed bytes.
     */
    @SuppressWarnings({
            "java:S127", // for" loop stop conditions should be invariant
    })
    public static byte[] processBytes(final StreamCipher cipher, final byte[] input) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        for (var output = new byte[Math.max(input.length, 1)]; ; ) {
            try {
                final var processed = cipher.processBytes(input, 0, input.length, output, 0);
                return Arrays.copyOf(output, processed);
            } catch (final DataLengthException dle) {
                System.err.println("doubling up output.length from " + output.length);
                Arrays.fill(output, (byte) 0);
                output = new byte[output.length << 1];
            }
        }
    }

    public static byte[] encrypt(final StreamCipher cipher, final CipherParameters params, final byte[] input) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        return processBytes(
                initForEncryption(cipher, params),
                input
        );
    }

    public static byte[] decrypt(final StreamCipher cipher, final CipherParameters params, final byte[] input) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        return processBytes(
                initForDecryption(cipher, params),
                input
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static long processAllBytes(final StreamCipher cipher, final InputStream in, final OutputStream out,
                                       final byte[] inbuf, byte[] outbuf)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "input is null");
        Objects.requireNonNull(out, "output is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        if (Objects.requireNonNull(outbuf, "outbuf is null").length == 0) {
            throw new IllegalArgumentException("outbuf.length is zero");
        }
        var written = 0L;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            while (true) {
                try {
                    final var processed = cipher.processBytes(inbuf, 0, r, outbuf, 0);
                    out.write(outbuf, 0, processed);
                    written += processed;
                    break;
                } catch (final DataLengthException dle) {
                    System.err.println("doubling up outbuf.length from " + outbuf.length);
                    Arrays.fill(outbuf, (byte) 0);
                    outbuf = new byte[outbuf.length << 1];
                }
            }
        }
        return written;
    }

    /**
     * Process all bytes, using specified cipher, from specified input stream, and writes processed bytes to specified
     * output.
     *
     * @param cipher the cipher.
     * @param in     the input stream from which bytes are read.
     * @param out    the output stream to which processed bytes are written.
     * @param inbuf  a buffer for reading bytes from {@code input}.
     * @return the number of bytes written to the {@code output}.
     * @throws IOException if an I/O error occurs.
     */
    public static long processAllBytes(final StreamCipher cipher, final InputStream in, final OutputStream out,
                                       final byte[] inbuf)
            throws IOException {
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        return processAllBytes(cipher, in, out, inbuf, new byte[inbuf.length]);
    }

    public static long encrypt(final StreamCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf, byte[] outbuf)
            throws IOException {
        return processAllBytes(
                initForEncryption(cipher, params),
                in,
                out,
                inbuf,
                outbuf
        );
    }

    public static long decrypt(final StreamCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf, byte[] outbuf)
            throws IOException {
        return processAllBytes(
                initForDecryption(cipher, params),
                in,
                out,
                inbuf,
                outbuf
        );
    }

    public static long encrypt(final StreamCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf)
            throws IOException {
        return processAllBytes(
                initForEncryption(cipher, params),
                in,
                out,
                inbuf
        );
    }

    public static long decrypt(final StreamCipher cipher, final CipherParameters params, final InputStream in,
                               final OutputStream out, final byte[] inbuf)
            throws IOException {
        return processAllBytes(
                initForDecryption(cipher, params),
                in,
                out,
                inbuf
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaStreamCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
