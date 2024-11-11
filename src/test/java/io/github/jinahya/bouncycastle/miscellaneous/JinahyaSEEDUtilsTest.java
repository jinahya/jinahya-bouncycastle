package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

class JinahyaSEEDUtilsTest {

    @Test
    void _CBC_PKCS5Padding_bytes() {
        // ------------------------------------------------------------------------------------------------------- given
        final var key = _Random_TestUtils.newRandomBytes(JinahyaSEEDUtils.BLOCK_BYTES);
        final var iv = _Random_TestUtils.newRandomBytes(JinahyaSEEDUtils.BLOCK_BYTES);
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        // -------------------------------------------------------------------------------------------------------- when
        final var encrypted = JinahyaSEEDUtils.encrypt_CBC_PKCS5Padding(key, iv, plain);
        final var decrypted = JinahyaSEEDUtils.decrypt_CBC_PKCS5Padding(key, iv, encrypted);
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
    }

    @Test
    void _CBC_PKCS5Padding_stream() throws IOException {
        // ------------------------------------------------------------------------------------------------------- given
        final var key = _Random_TestUtils.newRandomBytes(JinahyaSEEDUtils.BLOCK_BYTES);
        final var iv = _Random_TestUtils.newRandomBytes(JinahyaSEEDUtils.BLOCK_BYTES);
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1048576));
        // -------------------------------------------------------------------------------------------------------- when
        final byte[] encrypted;
        {
            final var in = new ByteArrayInputStream(plain);
            final var out = new ByteArrayOutputStream();
            final var inlen = ThreadLocalRandom.current().nextInt(8192) + 1;
            final var bytes = JinahyaSEEDUtils.encrypt_CBC_PKCS5Padding(key, iv, in, out, inlen);
            assert bytes >= plain.length;
            encrypted = out.toByteArray();
        }
        final byte[] decrypted;
        {
            final var in = new ByteArrayInputStream(encrypted);
            final var out = new ByteArrayOutputStream();
            final var inlen = ThreadLocalRandom.current().nextInt(8192) + 1;
            final var bytes = JinahyaSEEDUtils.decrypt_CBC_PKCS5Padding(key, iv, in, out, inlen);
            assert bytes <= encrypted.length;
            decrypted = out.toByteArray();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
    }
}