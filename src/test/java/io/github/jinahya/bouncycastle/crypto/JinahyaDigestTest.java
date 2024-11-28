package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._Digest_TestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ThreadLocalRandom;

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
            final var digest = _Digest_TestUtils.newRandomDigest();
            final var jinahya = new JinahyaDigest(digest);
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            final var out = jinahya.digest(in);
            assertThat(out).isNotNull().hasSize(digest.getDigestSize());
        }

        @Test
        void __SHA1() throws NoSuchAlgorithmException {
            // --------------------------------------------------------------------------------------------------- given
            final var digest = new SHA1Digest();
            final var jinahya = new JinahyaDigest(digest);
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            // ---------------------------------------------------------------------------------------------------- when
            final var out = jinahya.digest(in);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(out)
                    .isNotNull()
                    .hasSize(digest.getDigestSize())
                    .isEqualTo(MessageDigest.getInstance("SHA1").digest(in));
        }

        @Test
        void __SHA256() throws NoSuchAlgorithmException {
            // --------------------------------------------------------------------------------------------------- given
            final var digest = new SHA256Digest();
            final var jinahya = new JinahyaDigest(digest);
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            // ---------------------------------------------------------------------------------------------------- when
            final var out = jinahya.digest(in);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(out)
                    .isNotNull()
                    .hasSize(digest.getDigestSize())
                    .isEqualTo(MessageDigest.getInstance("SHA256").digest(in));
        }
    }

    @DisplayName("digest(in, inbuf)")
    @Nested
    class DigestAllTest {

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

        @Test
        void __SHA1() throws IOException, NoSuchAlgorithmException {
            // --------------------------------------------------------------------------------------------------- given
            final var digest = new SHA1Digest();
            final var jinahya = new JinahyaDigest(digest);
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
            // ---------------------------------------------------------------------------------------------------- when
            final var out = jinahya.digestAll(new ByteArrayInputStream(in), inbuf);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(out)
                    .isNotNull()
                    .hasSize(digest.getDigestSize())
                    .isEqualTo(MessageDigest.getInstance("SHA1").digest(in));
        }

        @Test
        void __SHA256() throws IOException, NoSuchAlgorithmException {
            // --------------------------------------------------------------------------------------------------- given
            final var digest = new SHA256Digest();
            final var jinahya = new JinahyaDigest(digest);
            final var in = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128));
            final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
            // ---------------------------------------------------------------------------------------------------- when
            final var out = jinahya.digestAll(new ByteArrayInputStream(in), inbuf);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(out)
                    .isNotNull()
                    .hasSize(digest.getDigestSize())
                    .isEqualTo(MessageDigest.getInstance("SHA256").digest(in));
        }
    }
}