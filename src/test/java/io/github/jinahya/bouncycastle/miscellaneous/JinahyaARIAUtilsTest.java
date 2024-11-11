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

    @DisplayName("_CBC_PKCS5Padding")
    @Nested
    class _CBC_PKCS5PaddingTest {

        @Test
        void _CBC_PKCS5Padding_bytes() {
            // ------------------------------------------------------------------------------------------------------- given
            final var key = _Random_TestUtils.newRandomBytes(_ARIA__Constants.BLOCK_BYTES);
            final var iv = _Random_TestUtils.newRandomBytes(_ARIA__Constants.BLOCK_BYTES);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            // -------------------------------------------------------------------------------------------------------- when
            final var encrypted = JinahyaARIAUtils.encrypt_CBC_PKCS5Padding(key, iv, plain);
            final var decrypted = JinahyaARIAUtils.decrypt_CBC_PKCS5Padding(key, iv, encrypted);
            // -------------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
        }

        @Test
        void _CBC_PKCS5Padding_stream() throws IOException {
            // ------------------------------------------------------------------------------------------------------- given
            final var key = _Random_TestUtils.newRandomBytes(_ARIA__Constants.BLOCK_BYTES);
            final var iv = _Random_TestUtils.newRandomBytes(_ARIA__Constants.BLOCK_BYTES);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1048576));
            // -------------------------------------------------------------------------------------------------------- when
            final byte[] encrypted;
            {
                final var in = new ByteArrayInputStream(plain);
                final var out = new ByteArrayOutputStream();
                final var inlen = ThreadLocalRandom.current().nextInt(8192) + 1;
                final var bytes = JinahyaARIAUtils.encrypt_CBC_PKCS5Padding(key, iv, in, out, inlen);
                assert bytes >= plain.length;
                encrypted = out.toByteArray();
            }
            final byte[] decrypted;
            {
                final var in = new ByteArrayInputStream(encrypted);
                final var out = new ByteArrayOutputStream();
                final var inlen = ThreadLocalRandom.current().nextInt(8192) + 1;
                final var bytes = JinahyaARIAUtils.decrypt_CBC_PKCS5Padding(key, iv, in, out, inlen);
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
            final var key = _Random_TestUtils.newRandomBytes(_ARIA__Constants.BLOCK_BYTES);
            final var tLen = __GCM_Constants.ALLOWED_T_LEN_LIST_GCM.get(
                    ThreadLocalRandom.current().nextInt(__GCM_Constants.ALLOWED_T_LEN_LIST_GCM.size())
            );
            final var iv = _Random_TestUtils.newRandomBytes(
                    ThreadLocalRandom.current().nextInt(128) + __GCM_Constants.IV_SIZE_GCM_MINIMUM
            );
            final var aad = ThreadLocalRandom.current().nextBoolean()
                    ? null
                    : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
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
            final var key = _Random_TestUtils.newRandomBytes(_ARIA__Constants.BLOCK_BYTES);
            final var tLen = __GCM_Constants.ALLOWED_T_LEN_LIST_GCM.get(
                    ThreadLocalRandom.current().nextInt(__GCM_Constants.ALLOWED_T_LEN_LIST_GCM.size())
            );
            final var iv = _Random_TestUtils.newRandomBytes(
                    ThreadLocalRandom.current().nextInt(128) + __GCM_Constants.IV_SIZE_GCM_MINIMUM
            );
            final var aad = ThreadLocalRandom.current().nextBoolean()
                    ? null
                    : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            // ---------------------------------------------------------------------------------------------------- when
            final byte[] encrypted;
            {
                final var in = new ByteArrayInputStream(plain);
                final var out = new ByteArrayOutputStream();
                final var inlen = ThreadLocalRandom.current().nextInt(8192) + 1;
                final var bytes = JinahyaARIAUtils.encrypt_GMM_NoPadding(key, tLen, iv, aad, in, out, inlen);
                assert bytes >= plain.length;
                encrypted = out.toByteArray();
            }
            final byte[] decrypted;
            {
                final var in = new ByteArrayInputStream(encrypted);
                final var out = new ByteArrayOutputStream();
                final var inlen = ThreadLocalRandom.current().nextInt(8192) + 1;
                final var bytes = JinahyaARIAUtils.decrypt_GMM_NoPadding(key, tLen, iv, aad, in, out, inlen);
                assert bytes <= encrypted.length;
                decrypted = out.toByteArray();
            }
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
        }
    }
}