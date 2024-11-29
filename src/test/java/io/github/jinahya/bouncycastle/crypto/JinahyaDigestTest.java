package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._Digest_TestUtils;
import io.github.jinahya.bouncycastle.jce.provider.JinahyaBouncyCastleProviderConstants;
import io.github.jinahya.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import org.bouncycastle.crypto.Digest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
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

    @DisplayName("digest(in)")
    @Nested
    class DigestArrayTest {

        private static Stream<Digest> getDigestStream() {
            return _Digest_TestUtils.getDigestStream();
        }

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

        @MethodSource({"getDigestStream"})
        @ParameterizedTest
        void __(final Digest digest) throws NoSuchAlgorithmException, NoSuchProviderException {
            JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
            // --------------------------------------------------------------------------------------------------- given
            final var jinahya = new JinahyaDigest(digest);
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            // ---------------------------------------------------------------------------------------------------- when
            final var out = jinahya.digest(in);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(out).isNotNull().hasSize(digest.getDigestSize()).isEqualTo(
                    MessageDigest.getInstance(
                                    digest.getAlgorithmName(),
                                    JinahyaBouncyCastleProviderConstants.BOUNCY_CASTLE_PROVIDER_NAME)
                            .digest(in)
            );
        }
    }

    @DisplayName("digestAll(in, inbuf)")
    @Nested
    class DigestAllToArrayTest {

        private static Stream<Digest> getDigestStream() {
            return _Digest_TestUtils.getDigestStream();
        }

        @Test
        void __() throws IOException {
            final var digest = _Digest_TestUtils.newRandomDigest();
            final var jinahya = new JinahyaDigest(digest);
            final var in = new ByteArrayInputStream(
                    _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128))
            );
            final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
            final var out = jinahya.digestAll(in, inbuf);
            assertThat(out)
                    .isNotNull()
                    .hasSize(digest.getDigestSize());
        }

        @MethodSource({"getDigestStream"})
        @ParameterizedTest
        void __(final Digest digest) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
            JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
            // --------------------------------------------------------------------------------------------------- given
            final var jinahya = new JinahyaDigest(digest);
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
            // ---------------------------------------------------------------------------------------------------- when
            final var out = jinahya.digestAll(new ByteArrayInputStream(in), inbuf);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(out)
                    .isNotNull()
                    .hasSize(digest.getDigestSize())
                    .isEqualTo(
                            MessageDigest.getInstance(
                                            digest.getAlgorithmName(),
                                            JinahyaBouncyCastleProviderConstants.BOUNCY_CASTLE_PROVIDER_NAME)
                                    .digest(in)
                    );
        }
    }
}