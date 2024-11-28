package _java.nio;

import java.nio.ByteBuffer;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _ByteBufferUtils {

    @Deprecated
    public static byte[] get(final ByteBuffer buffer, int index, final byte[] dst, int offset, final int length) {
        assert buffer != null;
        assert index >= 0;
        assert dst != null;
        assert offset >= 0;
        assert length >= 0;
        assert (offset + length) <= dst.length;
        assert (index + length) <= buffer.capacity();
        for (int l = offset + length; offset < l; ) {
            dst[offset++] = buffer.get(index++);
        }
        return dst;
    }

    @Deprecated
    public static byte[] get(final ByteBuffer buffer, int index, final byte[] dst, final int offset) {
        return get(buffer, index, dst, offset, dst.length - offset);
    }

    @Deprecated
    public static byte[] get(final ByteBuffer buffer, final int index, final byte[] dst) {
        return get(buffer, index, dst, 0);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Deprecated
    public static ByteBuffer put(final ByteBuffer buffer, int index, final byte[] src, int offset, final int length) {
        assert buffer != null;
        assert index >= 0;
        assert src != null;
        assert offset >= 0;
        assert length >= 0;
        assert (offset + length) <= src.length;
        assert (index + length) <= buffer.capacity();
        for (int l = offset + length; offset < l; ) {
            buffer.put(index++, src[offset++]);
        }
        return buffer;
    }

    @Deprecated
    public static ByteBuffer put(final ByteBuffer buffer, int index, final byte[] src, int offset) {
        return put(buffer, index, src, offset, src.length - offset);
    }

    @Deprecated
    public static ByteBuffer put(final ByteBuffer buffer, int index, final byte[] src) {
        return put(buffer, index, src, 0);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _ByteBufferUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
