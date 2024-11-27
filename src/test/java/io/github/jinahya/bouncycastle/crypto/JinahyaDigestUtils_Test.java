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
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A class for testing {@link JinahyaDigestUtils} class.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@NoArgsConstructor(access = AccessLevel.PACKAGE)
class JinahyaDigestUtils_Test {

    private static Stream<Digest> getRandomDigest() {
        return Stream.of(_Digest_TestUtils.newRandomDigest());
    }

    @DisplayName("update(digest, in, inoff, inlen)")
    @Nested
    class UpdateTest {

        private static Stream<Digest> getRandomDigest() {
            return JinahyaDigestUtils_Test.getRandomDigest();
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
            return JinahyaDigestUtils_Test.getRandomDigest();
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
            return JinahyaDigestUtils_Test.getRandomDigest();
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
            return JinahyaDigestUtils_Test.getRandomDigest();
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
}