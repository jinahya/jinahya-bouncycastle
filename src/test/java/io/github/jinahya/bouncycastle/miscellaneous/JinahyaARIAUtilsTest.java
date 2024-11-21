package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

class JinahyaARIAUtilsTest {

    @DisplayName("_CBC_PKCS7Padding")
    @Nested
    class _CBC_PKCS7PaddingTest {

        @Test
        void _CBC_PKCS7Padding_bytes() {
            // ------------------------------------------------------------------------------------------------------- given
            final var key = _ARIA__TestUtils.randomKey();
            final var iv = __CBC_TestUtils.newRandomIv(_ARIA___Constants.BLOCK_BYTES);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            // -------------------------------------------------------------------------------------------------------- when
            final var encrypted = JinahyaARIAUtils.encrypt_CBC_PKCS7Padding(key, iv, plain);
            final var decrypted = JinahyaARIAUtils.decrypt_CBC_PKCS7Padding(key, iv, encrypted);
            // -------------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
        }

        @Test
        void _CBC_PKCS7Padding_stream() throws IOException {
            // ------------------------------------------------------------------------------------------------------- given
            final var key = _ARIA__TestUtils.randomKey();
            final var iv = __CBC_TestUtils.newRandomIv(_ARIA___Constants.BLOCK_BYTES);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1048576));
            // -------------------------------------------------------------------------------------------------------- when
            final byte[] encrypted;
            {
                final var in = new ByteArrayInputStream(plain);
                final var out = new ByteArrayOutputStream();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
                final var bytes = JinahyaARIAUtils.encrypt_CBC_PKCS7Padding(key, iv, in, out, inbuf);
                assert bytes >= plain.length;
                encrypted = out.toByteArray();
            }
            final byte[] decrypted;
            {
                final var in = new ByteArrayInputStream(encrypted);
                final var out = new ByteArrayOutputStream();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
                final var bytes = JinahyaARIAUtils.decrypt_CBC_PKCS7Padding(key, iv, in, out, inbuf);
                assert bytes <= encrypted.length;
                decrypted = out.toByteArray();
            }
            // -------------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
        }
    }

    @DisplayName("_GCM_NoPadding")
    @Nested
    class _GCM_NoPadding_Test {

        @Test
        void __bytes() {
            // --------------------------------------------------------------------------------------------------- given
            final var key = _ARIA__TestUtils.randomKey();
            final var tLen = __GCM_TestUtils.randomTLen();
            final var iv = __GCM_TestUtils.randomIv();
            final var aad = __GCM_TestUtils.randomAad();
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            // ---------------------------------------------------------------------------------------------------- when
            final var encrypted = JinahyaARIAUtils.encrypt_GCM_NoPadding(key, tLen, iv, aad, plain);
            final var decrypted = JinahyaARIAUtils.decrypt_GCM_NoPadding(key, tLen, iv, aad, encrypted);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
        }

        @Test
        void __stream() throws IOException {
            // --------------------------------------------------------------------------------------------------- given
            final var key = _ARIA__TestUtils.randomKey();
            final var tLen = __GCM_TestUtils.randomTLen();
            final var iv = __GCM_TestUtils.randomIv();
            final var aad = __GCM_TestUtils.randomAad();
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1048576));
            // ---------------------------------------------------------------------------------------------------- when
            final byte[] encrypted;
            {
                final var in = new ByteArrayInputStream(plain);
                final var out = new ByteArrayOutputStream();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
                final var bytes = JinahyaARIAUtils.encrypt_GMM_NoPadding(key, tLen, iv, aad, in, out, inbuf);
                assert bytes >= plain.length;
                encrypted = out.toByteArray();
            }
            final byte[] decrypted;
            {
                final var in = new ByteArrayInputStream(encrypted);
                final var out = new ByteArrayOutputStream();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
                final var bytes = JinahyaARIAUtils.decrypt_GMM_NoPadding(key, tLen, iv, aad, in, out, inbuf);
                assert bytes <= encrypted.length;
                decrypted = out.toByteArray();
            }
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
        }
    }
}