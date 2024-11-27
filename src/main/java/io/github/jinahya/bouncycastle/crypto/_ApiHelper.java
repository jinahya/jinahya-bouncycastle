package io.github.jinahya.bouncycastle.crypto;

import java.util.Objects;

final class _ApiHelper {

    static <T> T requireNonNull(final String name, final T value) {
        return Objects.requireNonNull(value, name + " is null");
    }

    static int requireNonNegative(final String name, final int value) {
        if (value < 0) {
            throw new IllegalArgumentException(name + "(" + value + ") is negative");
        }
        return value;
    }

    static void requireValidBuf(final String prefix, final byte[] buf) {
        requireNonNull(prefix, buf);
        if (buf.length == 0) {
            throw new IllegalArgumentException(prefix + "buf.length is zero");
        }
    }

    static void requireValidBufOff(final String prefix, final byte[] buf, final int off) {
        requireValidBuf(prefix, buf);
        requireNonNegative(prefix + "off", off);
        if (off > buf.length) {
            throw new IllegalArgumentException(
                    prefix + "off(" + off + ") > " + prefix + "buf.length(" + buf.length + ")"
            );
        }
    }

    static void requireValidBufOffLen(final String prefix, final byte[] buf, final int off, final int len) {
        requireValidBufOff(prefix, buf, off);
        requireNonNegative(prefix + "len", len);
        if ((off + len) > buf.length) {
            throw new IllegalArgumentException(
                    '(' + prefix + "off(" + off + ") + " + prefix + "len(" + len + ")) > "
                            + prefix + "buf.length(" + buf.length + ")");
        }
    }

    static void requireValid_InInoffInlen_OutOutOff(final byte[] in, final int inoff, final int inlen, final byte[] out,
                                                    final int outoff) {
        requireValidBufOffLen("in", in, inoff, inlen);
        requireValidBufOff("out", out, outoff);
    }

    public static void requireValid(final byte[] in, final int inoff, final int inlen) {
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
    }

    public static void requireValid(final byte[] in, final int inoff, final int inlen, final byte[] out,
                                    final int outoff) {
        requireValid(in, inoff, inlen);
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if (outoff > out.length) {
            throw new IndexOutOfBoundsException("outoff(" + outoff + ") > out.length(" + out.length + ")");
        }
    }

    private _ApiHelper() {
        throw new AssertionError("instantiation is not allowed");
    }
}
