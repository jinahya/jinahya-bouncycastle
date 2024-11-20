package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.IntFunction;

/**
 * A utility class for {@link org.bouncycastle.crypto.AsymmetricBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a
 * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/AsymmetricBlockCipher.html">org.bouncycastle.crypto.AsymmetricBlockCipher</a>
 * (bcprov-jdk18on-javadoc)
 */
public final class JinahyaAsymmetricBlockCipherUtils {

    public static int getInputBlockCount(final AsymmetricBlockCipher cipher, final int inlen) {
        var count = inlen / cipher.getInputBlockSize();
        if (inlen % cipher.getInputBlockSize() > 0) {
            count++;
        }
        return count;
    }

    public static int getOutLen(final AsymmetricBlockCipher cipher, final int inlen) {
        final int blocks = JinahyaAsymmetricBlockCipherUtils.getInputBlockCount(cipher, inlen);
        return blocks * cipher.getOutputBlockSize();
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static <T extends AsymmetricBlockCipher> T initFor(final T cipher, final boolean encryption,
                                                               final CipherParameters params) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(params, "params is null");
        cipher.init(encryption, params);
        return cipher;
    }

    public static <T extends AsymmetricBlockCipher> T initForEncryption(final T cipher, final CipherParameters params) {
        return initFor(cipher, true, params);
    }

    public static <T extends AsymmetricBlockCipher> T initForDecryption(final T cipher, final CipherParameters params) {
        return initFor(cipher, false, params);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Processes, using specified cipher, bytes in specified range of specified input array, put processed bytes on
     * specified output array starting at specified index.
     *
     * @param cipher the cipher.
     * @param in     the input array.
     * @param inoff  a starting index of the {@code in}.
     * @param inlen  the number of bytes to process.
     * @param out    the output array onto which processed bytes are set.
     * @param outoff the starting index of the {@code out} onto which processed bytes are set.
     * @return the number of byte set on the {@code out}.
     * @throws InvalidCipherTextException when thrown from
     *                                    {@link AsymmetricBlockCipher#processBlock(byte[], int, int)
     *                                    cipher.processBlock}.
     */
    public static int processBlock(final AsymmetricBlockCipher cipher, final byte[] in, final int inoff,
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
        if ((inoff + inlen) > in.length) {
            throw new IndexOutOfBoundsException(
                    "inoff(" + inoff + ") + inlen(" + inlen + ") > in.length(" + in.length + ")"
            );
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if (outoff > out.length) {
            throw new IndexOutOfBoundsException("outoff(" + outoff + ") > out.length(" + out.length + ")");
        }
        final var cipherInputBlockSize = cipher.getInputBlockSize();
        if (inlen > cipherInputBlockSize) {
            throw new IllegalArgumentException(
                    "inlen(" + inlen + ") > cipher.inputBlockSize(" + cipherInputBlockSize + ")"
            );
        }
        final var outputBlockSize = cipher.getOutputBlockSize();
        if ((out.length - outoff) > outputBlockSize) {
            throw new IllegalArgumentException(
                    "out.length(" + out.length + ") - outoff(" + outoff + ") > " +
                            "cipher.outputBlockSize(" + outputBlockSize + ")"
            );
        }
        return JinahyaAsymmetricBlockCipherUtils_.processBlock(
                cipher,
                in,
                inoff,
                inlen,
                out,
                outoff
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    static void validateNonNull(final AsymmetricBlockCipher cipher, final ByteBuffer input, final ByteBuffer output) {
        assert cipher != null;
        assert input != null;
        assert output != null;
        final var inputBlockSize = cipher.getInputBlockSize();
        final var inputRemaining = input.remaining();
        if (inputRemaining > inputBlockSize) {
            throw new IllegalArgumentException(
                    "input.remaining(" + inputRemaining + ") > cipher.inputBlockSize(" + inputBlockSize + ")"
            );
        }
        final var outputBlockSize = cipher.getOutputBlockSize();
        final var outputRemaining = output.remaining();
        if (outputRemaining < outputBlockSize) {
            throw new IllegalArgumentException(
                    "output.remaining(" + outputRemaining + ") < cipher.outputBlockSize(" + outputBlockSize + ")"
            );
        }
    }

    /**
     * Process, using specified cipher, a block bytes from specified input buffer, and writes processed block bytes to
     * specified output buffer.
     *
     * @param cipher the cipher.
     * @param input  the input buffer.
     * @param output the output buffer onto which processed block bytes are put.
     * @return the number of bytes put onto the {@code output}.
     * @throws InvalidCipherTextException when failed to process.
     * @see AsymmetricBlockCipher#processBlock(byte[], int, int)
     */
    public static int processBlock(final AsymmetricBlockCipher cipher, final ByteBuffer input, final ByteBuffer output)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        validateNonNull(cipher, input, output);
        return JinahyaAsymmetricBlockCipherUtils_.processBlock(cipher, input, output);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static long processAllBlocks(
            final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out, final byte[] inbuf,
            final byte[] outbuf,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> inconsumer,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> outconsumer)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        final var inputBlockSize = cipher.getInputBlockSize();
        if (Objects.requireNonNull(inbuf, "inbuf is null").length < inputBlockSize) {
            throw new IllegalArgumentException(
                    "inbuf.length(" + inbuf.length + " < cipher.inputBlockSize(" + inputBlockSize + ")"
            );
        }
        final var outputBlockSize = cipher.getOutputBlockSize();
        if (Objects.requireNonNull(outbuf, "outbuf is null").length < cipher.getOutputBlockSize()) {
            throw new IllegalArgumentException(
                    "outbuf.length(" + outbuf.length + ") < cipher.outputBlockSize(" + outputBlockSize + ")"
            );
        }
        Objects.requireNonNull(inconsumer, "inconsumer is null");
        Objects.requireNonNull(outconsumer, "outconsumer is null");
        return JinahyaAsymmetricBlockCipherUtils_.processAllBlocks(
                cipher,
                in,
                out,
                inbuf,
                outbuf,
                inconsumer,
                outconsumer
        );
    }

    static long processAllBytes(
            final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out,
            final byte[] inbuf, final byte[] outbuf,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> inconsumer,
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> outconsumer)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        final var inputBlockSize = cipher.getInputBlockSize();
        if (Objects.requireNonNull(inbuf, "inbuf is null").length < inputBlockSize) {
            throw new IllegalArgumentException(
                    "inbuf.length(" + inbuf.length + " < cipher.inputBlockSize(" + inputBlockSize + ")"
            );
        }
        final var outputBlockSize = cipher.getOutputBlockSize();
        if (Objects.requireNonNull(outbuf, "outbuf is null").length < cipher.getOutputBlockSize()) {
            throw new IllegalArgumentException(
                    "outbuf.length(" + outbuf.length + ") < cipher.outputBlockSize(" + outputBlockSize + ")"
            );
        }
        return JinahyaAsymmetricBlockCipherUtils_.processAllBytes(
                cipher,
                in,
                out,
                inbuf,
                outbuf,
                inconsumer,
                outconsumer
        );
    }

//    @Deprecated
//    static long processAllBytes(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out,
//                                final byte[] inbuf, final byte[] outbuf)
//            throws IOException, InvalidCipherTextException {
//        Objects.requireNonNull(cipher, "cipher is null");
//        Objects.requireNonNull(in, "in is null");
//        Objects.requireNonNull(out, "out is null");
//        final var inputBlockSize = cipher.getInputBlockSize();
//        if (Objects.requireNonNull(inbuf, "inbuf is null").length < inputBlockSize) {
//            throw new IllegalArgumentException(
//                    "inbuf.length(" + inbuf.length + " < cipher.inputBlockSize(" + inputBlockSize + ")"
//            );
//        }
//        final var outputBlockSize = cipher.getOutputBlockSize();
//        if (Objects.requireNonNull(outbuf, "outbuf is null").length < cipher.getOutputBlockSize()) {
//            throw new IllegalArgumentException(
//                    "outbuf.length(" + outbuf.length + ") < cipher.outputBlockSize(" + outputBlockSize + ")"
//            );
//        }
//        return JinahyaAsymmetricBlockCipherUtils.processAllBytes(cipher, in, out, inbuf, outbuf);
//    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAsymmetricBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
