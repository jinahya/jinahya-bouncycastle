package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._Digest_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.crypto.Digest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A class for testing {@link JinahyaDigestUtils} class.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@NoArgsConstructor(access = AccessLevel.PACKAGE)
class JinahyaDigestUtilsTest {

    private static Stream<Digest> getRandomDigest() {
        return Stream.of(_Digest_TestUtils.newRandomDigest());
    }

    @DisplayName("update(digest, in, inoff, inlen)")
    @Nested
    class UpdateTest {

        private static Stream<Digest> getRandomDigest() {
            return JinahyaDigestUtilsTest.getRandomDigest();
        }

        @MethodSource({"getRandomDigest"})
        @ParameterizedTest
        void __(final Digest digest) {
            // --------------------------------------------------------------------------------------------------- given
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            // ---------------------------------------------------------------------------------------------------- when
            final var result = JinahyaDigestUtils.update(digest, plain, 0, plain.length);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(result).isSameAs(digest);
        }
    }

    @DisplayName("update(digest, in, inoff, inlen, out, outoff)")
    @Nested
    class UpdateAndDoFinalTest {

        private static Stream<Digest> getRandomDigest() {
            return JinahyaDigestUtilsTest.getRandomDigest();
        }

        @MethodSource({"getRandomDigest"})
        @ParameterizedTest
        void __(final Digest digest) {
            // --------------------------------------------------------------------------------------------------- given
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            final var out = new byte[digest.getDigestSize()];
            // ---------------------------------------------------------------------------------------------------- when
            final var bytes = JinahyaDigestUtils.updateAndDoFinal(digest, plain, 0, plain.length, out, 0);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(bytes).isSameAs(out.length);
        }
    }

    @DisplayName("updateAll(digest, in, inoff, inlen)")
    @Nested
    class UpdateAllTest {

        private static Stream<Digest> getRandomDigest() {
            return JinahyaDigestUtilsTest.getRandomDigest();
        }

        @MethodSource({"getRandomDigest"})
        @ParameterizedTest
        void __(final Digest digest) throws IOException {
            // --------------------------------------------------------------------------------------------------- given
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            // ---------------------------------------------------------------------------------------------------- when
            final var result = JinahyaDigestUtils.updateAll(
                    digest,
                    new ByteArrayInputStream(plain),
                    new byte[ThreadLocalRandom.current().nextInt(128) + 1]
            );
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(result).isSameAs(digest);
        }
    }

    @DisplayName("updateAll(digest, in, inoff, inlen, out, outoff)")
    @Nested
    class UpdateAllAndDoFinalTest {

        private static Stream<Digest> getRandomDigest() {
            return JinahyaDigestUtilsTest.getRandomDigest();
        }

        @MethodSource({"getRandomDigest"})
        @ParameterizedTest
        void __(final Digest digest) throws IOException {
            // --------------------------------------------------------------------------------------------------- given
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            final var out = new byte[digest.getDigestSize()];
            // ---------------------------------------------------------------------------------------------------- when
            final var bytes = JinahyaDigestUtils.updateAllAndDoFinal(
                    digest,
                    new ByteArrayInputStream(plain),
                    new byte[ThreadLocalRandom.current().nextInt(128) + 1],
                    out,
                    0
            );
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(bytes).isSameAs(out.length);
        }
    }

    @Nested
    class Update_Buffer_Test {

        private static Stream<Digest> getDigestStream() {
            return _Digest_TestUtils.getDigestStream();
        }

        @MethodSource({"getDigestStream"})
        @ParameterizedTest
        void __(final Digest digest) {
            // --------------------------------------------------------------------------------------------------- given
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            final var input = ByteBuffer.wrap(in);
            // ---------------------------------------------------------------------------------------------------- when
            final var result = JinahyaDigestUtils.update(digest, input);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(result).isSameAs(digest);
        }
    }

    @Nested
    class UpdateAndDoFinal_Buffer_Test {

        private static Stream<Digest> getDigestStream() {
            return _Digest_TestUtils.getDigestStream();
        }

        @MethodSource({"getDigestStream"})
        @ParameterizedTest
        void __(final Digest digest) {
            // --------------------------------------------------------------------------------------------------- given
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            final var input = ByteBuffer.wrap(in);
            final var output = ByteBuffer.allocate(digest.getDigestSize());
            // ---------------------------------------------------------------------------------------------------- when
            final var result = JinahyaDigestUtils.updateAndDoFinal(digest, input, output);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(result).isSameAs(output.capacity());
            assertThat(output.remaining()).isZero();
        }
    }

    @Nested
    class UpdateAllAndDoFinal_Buffer_Test {

        private static Stream<Digest> getDigestStream() {
            return _Digest_TestUtils.getDigestStream();
        }

        @MethodSource({"getDigestStream"})
        @ParameterizedTest
        void __(final Digest digest) throws IOException {
            // --------------------------------------------------------------------------------------------------- given
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            final var output = ByteBuffer.allocate(digest.getDigestSize());
            // ---------------------------------------------------------------------------------------------------- when
            final var result = JinahyaDigestUtils.updateAllAndDoFinal(
                    digest,
                    new ByteArrayInputStream(in),
                    new byte[ThreadLocalRandom.current().nextInt(128) + 1],
                    output
            );
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(result).isSameAs(output.capacity());
            assertThat(output.remaining()).isZero();
        }
    }
}