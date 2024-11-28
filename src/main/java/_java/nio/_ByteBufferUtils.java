package _java.nio;

import java.nio.ByteBuffer;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _ByteBufferUtils {

    /**
     * Absolute bulk get method equivalent to the {@link ByteBuffer#get(int, byte[], int, int)} method which is
     * available {@code 13+}.
     *
     * @param buffer the buffer.
     * @param index  a value of the {@code index} parameter.
     * @param dst    a value for the {@code dst} parameter.
     * @param offset a value for the {@code offset} parameter.
     * @param length a value for the {@code length} parameter.
     * @return the result of the invocation.
     * @see ByteBuffer#get(int, byte[], int, int)
     */
    @Deprecated(forRemoval = false)
    public static byte[] get(final ByteBuffer buffer, int index, final byte[] dst, int offset, final int length) {
        /*
         * index – The index in this buffer from which the first byte will be read;
         *         must be non-negative and less than <limit()>
         * offset – The offset within the array of the first byte to be written;
         *          must be non-negative and less than <dst.length>
         * length – The number of bytes to be written to the given array;
         *          must be non-negative and no larger than the smaller of <limit() - index> and <dst.length - offset>
         */
        assert buffer != null;
        assert index >= 0;
        assert index < buffer.limit();
        assert dst != null;
        assert offset >= 0;
        assert offset <= dst.length;
        assert length <= Math.min(buffer.limit() - index, dst.length - index);
        for (int l = offset + length; offset < l; ) {
            dst[offset++] = buffer.get(index++);
        }
        return dst;
    }

    @Deprecated(forRemoval = false)
    public static byte[] get(final ByteBuffer buffer, int index, final byte[] dst, final int offset) {
        return get(buffer, index, dst, offset, dst.length - offset);
    }

    @Deprecated(forRemoval = false)
    public static byte[] get(final ByteBuffer buffer, final int index, final byte[] dst) {
        return get(buffer, index, dst, 0);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Deprecated(forRemoval = false)
    public static ByteBuffer put(final ByteBuffer buffer, int index, final byte[] src, int offset, final int length) {
        /*
         * index – The index in this buffer at which the first byte will be written;
         *         must be non-negative and less than limit()
         * offset – The offset within the array of the first byte to be read;
         *          must be non-negative and less than src.length
         * length – The number of bytes to be read from the given array;
         *          must be non-negative and no larger than the smaller of <limit() - index> and <src.length - offset>
         */
        assert buffer != null;
        assert index >= 0;
        assert index < buffer.limit();
        assert src != null;
        assert offset >= 0;
        assert offset < src.length;
        assert length >= 0;
        assert length <= Math.min(buffer.limit() - index, src.length - offset);
        for (int l = offset + length; offset < l; ) {
            buffer.put(index++, src[offset++]);
        }
        return buffer;
    }

    @Deprecated(forRemoval = false)
    public static ByteBuffer put(final ByteBuffer buffer, int index, final byte[] src, int offset) {
        return put(buffer, index, src, offset, src.length - offset);
    }

    @Deprecated(forRemoval = false)
    public static ByteBuffer put(final ByteBuffer buffer, int index, final byte[] src) {
        return put(buffer, index, src, 0);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _ByteBufferUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
