package _java.nio;

import java.nio.ByteBuffer;

public final class _ByteBufferUtils {

    @Deprecated
    public static byte[] get(final ByteBuffer buffer, int index, final byte[] dst, int offset, final int length) {
        for (int l = offset + length; offset < l; ) {
            dst[offset++] = buffer.get(index++);
        }
        return dst;
    }

    @Deprecated
    public static byte[] get(final ByteBuffer buffer, final int index, final byte[] dst) {
        return get(buffer, index, dst, 0, dst.length);
    }

    private _ByteBufferUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
