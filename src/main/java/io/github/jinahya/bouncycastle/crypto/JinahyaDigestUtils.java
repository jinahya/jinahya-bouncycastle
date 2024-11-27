package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.Digest;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

public final class JinahyaDigestUtils {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Updates, to specified digest, bytes in specified range of specified input array.
     *
     * @param digest the digest.
     * @param in     the byte array to be updated to the {@code digest}.
     * @param inoff  starting index of {@code in}.
     * @param inlen  number of bytes from the {@code inoff} to update.
     * @param <T>    digest type parameter
     * @return given {@code digest}.
     * @see #updateAndDoFinal(Digest, byte[], int, int, byte[], int)
     */
    public static <T extends Digest> T update(final T digest, final byte[] in, final int inoff, final int inlen) {
        Objects.requireNonNull(digest, "digest is null");
        Objects.requireNonNull(in, "in is null");
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") is negative");
        }
        if (inlen < 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is negative");
        }
        if ((inoff + inlen) > in.length) {
            throw new IllegalArgumentException(
                    "inoff(" + inoff + ") + inlen(" + inlen + ") > in.length(" + in.length + ")");
        }
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
     * @see #updateAndDoFinal(Digest, byte[], int, int)
     */
    public static int updateAndDoFinal(final Digest digest, final byte[] in, final int inoff, final int inlen,
                                       final byte[] out, final int outoff) {
        Objects.requireNonNull(digest, "digest is null");
        Objects.requireNonNull(in, "in is null");
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") is negative");
        }
        if (inlen < 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is negative");
        }
        if ((inoff + inlen) > in.length) {
            throw new IllegalArgumentException(
                    "inoff(" + inoff + ") + inlen(" + inlen + ") > in.length(" + in.length + ")");
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        final var digestSize = digest.getDigestSize();
        if ((outoff + digest.getDigestSize()) > out.length) {
            throw new IllegalArgumentException(
                    "(outoff(" + outoff + ") + digest.digestSize(" + digestSize + ")) > out.length(" + out.length + ")"
            );
        }
        return JinahyaDigestUtils_.updateAndDoFinal(digest, in, inoff, inlen, out, outoff);
    }

    /**
     * Updates, to specified digest, bytes in specified range of specified input byte array, and returns the final
     * result.
     *
     * @param digest the digest.
     * @param in     the byte array to be updated to the {@code digest}.
     * @param inoff  starting index of {@code in}.
     * @param inlen  number of bytes from the {@code inoff} to update.
     * @return the final result.
     * @see #updateAndDoFinal(Digest, byte[], int, int, byte[], int)
     */
    public static byte[] updateAndDoFinal(final Digest digest, final byte[] in, final int inoff, final int inlen) {
        Objects.requireNonNull(digest, "digest is null");
        Objects.requireNonNull(in, "in is null");
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") is negative");
        }
        if (inlen < 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is negative");
        }
        if ((inoff + inlen) > in.length) {
            throw new IllegalArgumentException(
                    "inoff(" + inoff + ") + inlen(" + inlen + ") > in.length(" + in.length + ")");
        }
        final var out = new byte[digest.getDigestSize()];
        final var outlen = JinahyaDigestUtils_.updateAndDoFinal(digest, in, inoff, inlen, out, 0);
        assert outlen == out.length;
        return out;
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
        Objects.requireNonNull(digest, "digest is null");
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        return JinahyaDigestUtils_.updateAll(digest, in, inbuf);
    }

    /**
     * Updates, to specified digest, all bytes from specified input stream, finalizes, and set returns to the specified
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
     * @see #updateAllAndDoFinal(Digest, InputStream, byte[])
     */
    public static int updateAllAndDoFinal(final Digest digest, final InputStream in, final byte[] inbuf,
                                          final byte[] out, final int outoff)
            throws IOException {
        Objects.requireNonNull(digest, "digest is null");
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        final var digestSize = digest.getDigestSize();
        if ((outoff + digest.getDigestSize()) > out.length) {
            throw new IllegalArgumentException(
                    "(outoff(" + outoff + ") + digest.digestSize(" + digestSize + ")) > out.length(" + out.length + ")"
            );
        }
        return JinahyaDigestUtils_.updateAllAndDoFinal(digest, in, inbuf, out, outoff);
    }

    /**
     * Updates, to specified digest, all bytes from specified input stream, and returns the final result.
     *
     * @param digest the digest.
     * @param in     the input stream.
     * @param inbuf  a buffer for reading bytes from the input stream.
     * @return the final result.
     * @throws IOException if an I/O error occurs.
     * @see #updateAllAndDoFinal(Digest, InputStream, byte[], byte[], int)
     */
    public static byte[] updateAllAndDoFinal(final Digest digest, final InputStream in, final byte[] inbuf)
            throws IOException {
        Objects.requireNonNull(digest, "digest is null");
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        final var out = new byte[digest.getDigestSize()];
        final var outlen = JinahyaDigestUtils_.updateAllAndDoFinal(digest, in, inbuf, out, 0);
        assert outlen == out.length;
        return out;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaDigestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
