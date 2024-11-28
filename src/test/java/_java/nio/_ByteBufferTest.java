package _java.nio;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class _ByteBufferTest {

    @Nested
    class GetTest {

        @Test
        void __() {
            final var buffer = ByteBuffer.allocate(8).limit(7);
            assertThatThrownBy(() -> {
                buffer.get(0, new byte[buffer.capacity()]);
            }).isInstanceOf(IndexOutOfBoundsException.class);
        }

        @Test
        void absoluteBulkGet_PositionDoesNotChange_() {
            final var buffer = ByteBuffer.allocate(8).position(1).limit(7);
            final var position = buffer.position();
            assertThatCode(() -> {
                buffer.get(0, new byte[buffer.remaining()]);
            }).doesNotThrowAnyException();
            assertThat(buffer.position()).isEqualTo(position);
        }
    }
}