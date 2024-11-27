package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.Mac;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

public final class JinahyaMacUtils {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Updates, to specified mac, bytes in specified range of specified byte array.
     *
     * @param mac   the mac.
     * @param in    the byte array to be updated to the {@code mac}.
     * @param inoff starting index of {@code in}.
     * @param inlen number of bytes from the {@code inoff} to update.
     * @param <T>   mac type parameter
     * @return given {@code mac}.
     * @see #updateAndDoFinal(Mac, byte[], int, int, byte[], int)
     */
    public static <T extends Mac> T update(final T mac, final byte[] in, final int inoff, final int inlen) {
        Objects.requireNonNull(mac, "mac is null");
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
        return JinahyaMacUtils_.update(mac, in, inoff, inlen);
    }

    /**
     * Updates, to specified mac, bytes in specified range of specified byte array, finalizes, and set result to
     * specified output array starting at specified index.
     *
     * @param mac    the mac.
     * @param in     the byte array to be updated to the {@code mac}.
     * @param inoff  starting index of {@code in}.
     * @param inlen  number of bytes from the {@code inoff} to update.
     * @param out    the output array on which finalized bytes are set.
     * @param outoff starting index of {@code out}.
     * @return the number of bytes set on the {@code out}.
     * @see #update(Mac, byte[], int, int)
     */
    public static int updateAndDoFinal(final Mac mac, final byte[] in, final int inoff, final int inlen,
                                       final byte[] out, final int outoff) {
        Objects.requireNonNull(mac, "mac is null");
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
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if (outoff > out.length) {
            throw new IndexOutOfBoundsException("outoff(" + outoff + ") > out.length(" + out.length + ")");
        }
        final var macSize = mac.getMacSize();
        if ((outoff + mac.getMacSize()) > out.length) {
            throw new IllegalArgumentException(
                    "(outoff(" + outoff + ") + mac.macSize(" + macSize + ")) > out.length(" + out.length + ")"
            );
        }
        return JinahyaMacUtils_.updateAndDoFinal(mac, in, inoff, inlen, out, outoff);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Updates, to specified mac, all bytes from specified input stream.
     *
     * @param mac   the mac.
     * @param in    the input stream.
     * @param inbuf a buffer for reading bytes from the input stream.
     * @param <T>   mac type parameter
     * @return given {@code mac}.
     * @throws IOException if an I/O error occurs.
     * @see #updateAllAndDoFinal(Mac, InputStream, byte[], byte[], int)
     */
    public static <T extends Mac> T updateAll(final T mac, final InputStream in, final byte[] inbuf)
            throws IOException {
        Objects.requireNonNull(mac, "mac is null");
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        return JinahyaMacUtils_.updateAll(mac, in, inbuf);
    }

    /**
     * Updates, to specified mac, all bytes from specified input stream, finalizes, and set returns to the specified
     * output array starting at specified index.
     *
     * @param mac    the mac.
     * @param in     the input stream.
     * @param inbuf  a buffer for reading bytes from the input stream.
     * @param out    the output array on which finalized bytes are set.
     * @param outoff starting index of {@code out}.
     * @return the number of bytes set on the {@code out}.
     * @throws IOException if an I/O error occurs.
     * @see #updateAll(Mac, InputStream, byte[])
     */
    public static int updateAllAndDoFinal(final Mac mac, final InputStream in, final byte[] inbuf, final byte[] out,
                                          final int outoff)
            throws IOException {
        Objects.requireNonNull(mac, "mac is null");
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        final var macSize = mac.getMacSize();
        if ((outoff + mac.getMacSize()) > out.length) {
            throw new IllegalArgumentException(
                    "(outoff(" + outoff + ") + mac.macSize(" + macSize + ")) > out.length(" + out.length + ")"
            );
        }
        return JinahyaMacUtils_.updateAllAndDoFinal(mac, in, inbuf, out, outoff);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaMacUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
