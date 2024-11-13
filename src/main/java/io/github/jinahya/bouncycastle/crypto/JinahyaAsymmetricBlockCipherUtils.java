package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

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

    // -----------------------------------------------------------------------------------------------------------------
    private static void validate(final AsymmetricBlockCipher cipher, final byte[] in, final int inoff,
                                 final int inlen, final byte[] out, final int outoff) {
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
            throw new IndexOutOfBoundsException(
                    "outoff(" + outoff + ") + inlen(" + inlen + ") > in.length(" + in.length + ")"
            );
        }
    }

    /**
     * Processes, using specified cipher, all bytes int specified range of specified input array, put processed bytes on
     * specified output array starting at specified index.
     *
     * @param cipher the cipher.
     * @param in     the input array.
     * @param inoff  starting position of the {@code in}.
     * @param inlen  number of bytes to process.
     * @param out    the output array.
     * @param outoff the starting position of the {@code out}.
     * @return the number of byte set on the {@code out}.
     * @throws InvalidCipherTextException when thrown from
     *                                    {@link AsymmetricBlockCipher#processBlock(byte[], int, int)
     *                                    cipher.processBlock}.
     */
    public static int processBlocks(final AsymmetricBlockCipher cipher, final byte[] in, final int inoff,
                                    final int inlen, final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        validate(cipher, in, inoff, inlen, out, outoff);
        return JinahyaAsymmetricBlockCipherUtils_.processBlocks(
                cipher,
                in,
                inoff,
                inlen,
                out,
                outoff
        );
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Reads a block from specified input stream, processes, and writes to specified output stream.
     *
     * @param cipher a cipher for processing the block.
     * @param in     the input stream from which a block is read; should
     *               {@link InputStream#markSupported() support mark}.
     * @param out    the output stream to which the processed block is written.
     * @return {@code true} if a block has been read, processed, and written to the output stream; {@code false} if no
     * block has been read from the input stream.
     * @throws IllegalArgumentException   when {@code in} doesn't {@link InputStream#markSupported() support mark}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException when failed to process.
     * @see AsymmetricBlockCipher#processBlock(byte[], int, int)
     * @see #processAllBlocks(AsymmetricBlockCipher, InputStream, OutputStream, byte[])
     */
    static boolean processBlock(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        if (!Objects.requireNonNull(in, "in is null").markSupported()) {
            throw new IllegalArgumentException("in doesn't support mark");
        }
        Objects.requireNonNull(out, "out is null");
        return JinahyaAsymmetricBlockCipherUtils_.processBlock(cipher, in, out);
    }

    /**
     * Reads all available blocks from specified input stream, processes, and writes processed blocks to specified
     * output stream.
     *
     * @param cipher a cipher for processing blocks.
     * @param in     the input stream from which blocks are read; should
     *               {@link InputStream#markSupported() support mark}.
     * @param out    the output stream to which processed blocks are written.
     * @param inbuf  a buffer, for reading blocks from the input stream, whose {@code length} should be greater than or
     *               equals to {@link AsymmetricBlockCipher#getInputBlockSize() cipher.getInputBlockSize()}.
     * @return the number of blocks read, processed, and written.
     * @throws IllegalArgumentException   when {@code in} doesn't {@link InputStream#markSupported() support mark}.
     * @throws IllegalArgumentException   when {@code inbuf.length} is less than {@code cipher.getInputBlockSize()}.
     * @throws IOException                if an I/O error occurs.
     * @throws InvalidCipherTextException when failed to process.
     * @see AsymmetricBlockCipher#processBlock(byte[], int, int)
     * @see #processBlock(AsymmetricBlockCipher, InputStream, OutputStream)
     */
    public static long processAllBlocks(final AsymmetricBlockCipher cipher, final InputStream in,
                                        final OutputStream out, final byte[] inbuf)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        if (!Objects.requireNonNull(in, "in is null").markSupported()) {
            throw new IllegalArgumentException("in doesn't support mark");
        }
        Objects.requireNonNull(out, "out is null");
        {
            final var inputBlockSize = cipher.getInputBlockSize();
            if (Objects.requireNonNull(inbuf, "inbuf is null").length < inputBlockSize) {
                throw new IllegalArgumentException(
                        "inbuf.length(" + inbuf.length + ") < cipher.inputBlockSize(" + inputBlockSize + ")"
                );
            }
        }
        return JinahyaAsymmetricBlockCipherUtils_.processAllBlocks(cipher, in, out, inbuf);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAsymmetricBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
