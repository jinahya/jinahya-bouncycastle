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
