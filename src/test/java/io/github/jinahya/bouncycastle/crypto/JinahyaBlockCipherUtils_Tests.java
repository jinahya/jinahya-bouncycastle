package io.github.jinahya.bouncycastle.crypto;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.crypto.BlockCipher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.mockito.Mockito;

import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
class JinahyaBlockCipherUtils_Tests {

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("processBlock(cipher, in, inoff, out, outoff)")
    @Nested
    class ProcessBlockTest {

        @DisplayName("""
                should throw <NullPointerException>
                when <cipher> is <null>"""
        )
        @Test
        void _ShouldThrowNullPointerException_CipherIsNull() {
            final var cipher = Mockito.mock(BlockCipher.class);
            final var in = new byte[cipher.getBlockSize()];
            final var out = new byte[cipher.getBlockSize()];
            assertThatThrownBy(() -> {
                JinahyaBlockCipherUtils.processBlock(
                        null,
                        in,
                        0,
                        out,
                        0
                );
            }).isInstanceOf(NullPointerException.class);
        }

        @DisplayName("""
                should throw <NullPointerException>
                when <in> is <null>"""
        )
        @Test
        void _ShouldThrowNullPointerException_InIsNull() {
            final var cipher = Mockito.mock(BlockCipher.class);
            final var out = new byte[cipher.getBlockSize()];
            assertThatThrownBy(() -> {
                JinahyaBlockCipherUtils.processBlock(
                        cipher,
                        null,
                        0,
                        out,
                        0
                );
            }).isInstanceOf(NullPointerException.class);
        }

        @DisplayName("""
                should throw <IllegalArgumentException>
                when <inoff + cipher.blockSize> is greater than <in.length>"""
        )
        @Test
        void _ShouldThrowIllegalArgumentException_InLengthIsLessThanCipherBlockSize() {
            final var cipher = Mockito.mock(BlockCipher.class);
            BDDMockito.given(cipher.getBlockSize()).willReturn(1);
            final var in = new byte[cipher.getBlockSize()];
            final var inoff = ThreadLocalRandom.current().nextInt(in.length) + 1;
            assert inoff + cipher.getBlockSize() >= in.length;
            final var out = new byte[cipher.getBlockSize()];
            final var outoff = 0;
            assertThatThrownBy(() -> {
                JinahyaBlockCipherUtils.processBlock(
                        cipher,
                        in,
                        inoff,
                        out,
                        outoff
                );
            }).isInstanceOf(IllegalArgumentException.class);
        }
    }
}