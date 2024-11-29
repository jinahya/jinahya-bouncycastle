package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.Digest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Utilities related to {@link Digest} interface.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaDigest
 */
public final class JinahyaDigestUtils {

    private static <T> T requireNonNull_Digest(final T digest) {
        return Objects.requireNonNull(digest, "digest is null");
    }

    private static void requireValid_In_Inoff_Inlen(final byte[] in, final int inoff, final int inlen) {
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
    }

    private static void requireValid_Out_Outoff(final byte[] out, final int outoff, final int digestSize) {
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if ((outoff + digestSize) > out.length) {
            throw new IllegalArgumentException(
                    "(outoff(" + outoff + ") + digest.digestSize(" + digestSize + ")) > out.length(" + out.length + ")"
            );
        }
    }

    static void requireValid_Inbuf(final byte[] inbuf) {
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
    }

    static void requireValid_Output(final ByteBuffer output, final int digestSize) {
        assert digestSize > 0;
        if (Objects.requireNonNull(output, "output is null").remaining() < digestSize) {
            throw new IllegalArgumentException(
                    "output.remaining(" + output.remaining() + ") < digest.digestSize(" + digestSize + ")"
            );
        }
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Updates, to specified digest, bytes in specified range of specified input array.
     *
     * @param digest the digest.
     * @param in     the byte array to be updated to the {@code digest}.
     * @param inoff  a starting index of {@code in}.
     * @param inlen  a number of bytes from the {@code inoff} to update.
     * @param <T>    digest type parameter
     * @return given {@code digest}.
     * @see #updateAndDoFinal(Digest, byte[], int, int, byte[], int)
     * @see #update(Digest, ByteBuffer)
     */
    public static <T extends Digest> T update(final T digest, final byte[] in, final int inoff, final int inlen) {
        requireNonNull_Digest(digest);
        requireValid_In_Inoff_Inlen(in, inoff, inlen);
        return JinahyaDigestUtils_.update(digest, in, inoff, inlen);
    }

    /**
     * Updates, to specified digest, bytes in specified range of specified input array, finalizes, and set result to
     * specified output array starting at specified index.
     *
     * @param digest the digest.
     * @param in     the byte array to be updated to the {@code digest}.
     * @param inoff  starting index of {@code in}.
     * @param inlen  number of bytes from the {@code inoff} to update.
     * @param out    the output array on which finalized bytes are set.
     * @param outoff the starting index of {@code out}.
     * @return the number of bytes set on the {@code out}.
     * @see #update(Digest, byte[], int, int)
     */
    public static int updateAndDoFinal(final Digest digest, final byte[] in, final int inoff, final int inlen,
                                       final byte[] out, final int outoff) {
        requireNonNull_Digest(digest);
        requireValid_In_Inoff_Inlen(in, inoff, inlen);
        final var digestSize = digest.getDigestSize();
        requireValid_Out_Outoff(out, outoff, digestSize);
        return JinahyaDigestUtils_.updateAndDoFinal(digest, in, inoff, inlen, out, outoff, digestSize);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Updates, to specified digest, all bytes from specified input stream.
     *
     * @param digest the digest.
     * @param in     the input stream.
     * @param inbuf  a buffer for reading bytes from the input stream.
     * @param <T>    digest type parameter
     * @return given {@code digest}.
     * @throws IOException if an I/O error occurs.
     * @see #updateAllAndDoFinal(Digest, InputStream, byte[], byte[], int)
     */
    public static <T extends Digest> T updateAll(final T digest, final InputStream in, final byte[] inbuf)
            throws IOException {
        requireNonNull_Digest(digest);
        requireValid_Inbuf(inbuf);
        return JinahyaDigestUtils_.updateAll(digest, in, inbuf);
    }

    /**
     * Updates, to specified digest, all bytes from specified input stream, finalizes, and set result to specified
     * output array starting at specified index.
     *
     * @param digest the digest.
     * @param in     the input stream.
     * @param inbuf  a buffer for reading bytes from the input stream.
     * @param out    the output array on which finalized bytes are set.
     * @param outoff starting index of {@code out}.
     * @return the number of bytes set on the {@code out}.
     * @throws IOException if an I/O error occurs.
     * @see #updateAll(Digest, InputStream, byte[])
     */
    public static int updateAllAndDoFinal(final Digest digest, final InputStream in, final byte[] inbuf,
                                          final byte[] out, final int outoff)
            throws IOException {
        requireNonNull_Digest(digest);
        requireValid_Inbuf(inbuf);
        final var digestSize = digest.getDigestSize();
        requireValid_Out_Outoff(out, outoff, digestSize);
        return JinahyaDigestUtils_.updateAllAndDoFinal(digest, in, inbuf, out, outoff, digestSize);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Updates, to specified digest, remaining bytes of specified input buffer.
     *
     * @param digest the digest.
     * @param input  the input byte buffer whose remaining bytes are updated to the {@code digest}.
     * @param <T>    digest type parameter
     * @return given {@code digest}.
     * @throws NullPointerException if any of specified arguments is {@code null}.
     * @see #updateAndDoFinal(Digest, ByteBuffer, ByteBuffer)
     * @see #update(Digest, byte[], int, int)
     */
    public static <T extends Digest> T update(final T digest, final ByteBuffer input) {
        requireNonNull_Digest(digest);
        Objects.requireNonNull(input, "input is null");
        return JinahyaDigestUtils_.update(digest, input);
    }

    /**
     * Updates, to specified digest, remaining bytes of specified input buffer, finalizes, and put the result to
     * specified output buffer.
     *
     * @param digest the digest.
     * @param input  the input byte buffer whose remaining bytes are updated to the {@code digest}.
     * @param output the output byte buffer onto which the finalization result are put.
     * @return the number of bytes put on the {@code output}.
     * @throws NullPointerException     if any of specified arguments is {@code null}.
     * @throws IllegalArgumentException when {@link ByteBuffer#remaining() output.remaining} is less than
     *                                  {@link Digest#getDigestSize() cipher.digestSize}.
     */
    public static int updateAndDoFinal(final Digest digest, final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(digest, "digest is null");
        Objects.requireNonNull(input, "input is null");
        final var digestSize = digest.getDigestSize();
        requireValid_Output(output, digestSize);
        return JinahyaDigestUtils_.updateAndDoFinal(digest, input, output, digestSize);
    }

    /**
     * Updates, to specified digest, all bytes from specified input stream, finalizes, and put the result to specified
     * output buffer.
     *
     * @param digest the digest.
     * @param in     the input stream.
     * @param output the output byte buffer onto which the finalization result are put.
     * @return the number of bytes put on the {@code output}.
     * @throws NullPointerException     if any of specified arguments is {@code null}.
     * @throws IllegalArgumentException when {@code inbuf.length} is zero.
     * @throws IllegalArgumentException when {@link ByteBuffer#remaining() output.remaining} is less than
     *                                  {@link Digest#getDigestSize() cipher.digestSize}.
     * @throws IOException              when an I/O error occurs while reading bytes from the {@code in}.
     */
    public static int updateAllAndDoFinal(final Digest digest, final InputStream in, final byte[] inbuf,
                                          final ByteBuffer output)
            throws IOException {
        requireNonNull_Digest(digest);
        requireValid_Inbuf(inbuf);
        requireValid_Output(output, digest.getDigestSize());
        return JinahyaDigestUtils_.updateAllAndDoFinal(digest, in, inbuf, output);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaDigestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
