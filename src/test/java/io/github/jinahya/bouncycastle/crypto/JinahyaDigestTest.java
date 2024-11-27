package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.Digest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThatCode;

class JinahyaDigestTest {

    @DisplayName("JinahyaDigest(digest)")
    @Nested
    class ConstructorTest {

        @Test
        void _ThrowNullPointerException_DigestIsNull() {
            assertThatCode(() -> {
                new JinahyaDigest(null);
            }).isInstanceOf(NullPointerException.class);
        }
    }

    @DisplayName("digest([B)[B")
    @Nested
    class DigestTest {

        @DisplayName("should throw <NullPointerException> when <in> is <null>")
        @Test
        void _ThrowNullPointerException_InIsNull() {
            // --------------------------------------------------------------------------------------------------- given
            final var instance = new JinahyaDigest(Mockito.mock(Digest.class));
            // ----------------------------------------------------------------------------------------------- when/then
            assertThatCode(() -> {
                instance.digest(null);
            }).isInstanceOf(NullPointerException.class);
        }

        @Test
        void __() {
            final var digest = Mockito.mock(Digest.class);
        }
    }

    @Nested
    class DigestAllTest {

    }
}