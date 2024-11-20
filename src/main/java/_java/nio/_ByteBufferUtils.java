package _java.nio;

import java.nio.ByteBuffer;

public final class _ByteBufferUtils {

    @Deprecated
    public static <T extends ByteBuffer> T get(final T buffer, int index, final byte[] dst, int offset,
                                               final int length) {
        for (int l = offset + length; offset < l; ) {
            dst[offset++] = buffer.get(index++);
        }
        return buffer;
    }

    @Deprecated
    public static <T extends ByteBuffer> T get(final T buffer, int index, final byte[] dst) {
        return get(buffer, index, dst, 0, dst.length);
    }

    private _ByteBufferUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
