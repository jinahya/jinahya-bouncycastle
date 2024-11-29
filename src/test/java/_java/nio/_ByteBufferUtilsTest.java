package _java.nio;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThatCode;

class _ByteBufferUtilsTest {

    @DisplayName("get(buffer, index, dst, offset, length)")
    @Nested
    class GetBufferIndexDstOffsetLengthTest {

        @Test
        void _throwAssertionError_bufferIsNull() {
            assertThatCode(() -> {
                _ByteBufferUtils.get(
                        null,
                        0,
                        new byte[0],
                        0,
                        0
                );
            }).isInstanceOf(AssertionError.class);
        }

        @Test
        void _throwAssertionError_indexIsNegative() {
            assertThatCode(() -> {
                _ByteBufferUtils.get(
                        ByteBuffer.allocate(0),
                        ThreadLocalRandom.current().nextInt() | Integer.MIN_VALUE,
                        new byte[0],
                        0,
                        0
                );
            }).isInstanceOf(AssertionError.class);
        }

        @Test
        void _throwAssertionError_indexIsLessThanBufferLimit() {
            final var buffer = ByteBuffer.allocate(0);
            final var index = buffer.limit();
            assertThatCode(() -> {
                _ByteBufferUtils.get(
                        buffer,
                        index,
                        new byte[0],
                        0,
                        0
                );
            }).isInstanceOf(AssertionError.class);
        }
    }
}