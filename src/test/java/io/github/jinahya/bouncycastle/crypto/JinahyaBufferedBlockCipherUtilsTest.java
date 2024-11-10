package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class JinahyaBufferedBlockCipherUtilsTest {

    private static void __array(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
        // -------------------------------------------------------------------------------------------------------------
        final byte[] encrypted;
        {
            cipher.init(true, params);
            final var out = new byte[cipher.getOutputSize(plain.length)];
            final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    plain,
                    0,
                    plain.length,
                    out,
                    0
            );
            encrypted = Arrays.copyOf(out, outlen);
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] decrypted;
        {
            cipher.init(false, params);
            final var out = new byte[cipher.getOutputSize(encrypted.length)];
            final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    encrypted,
                    0,
                    encrypted.length,
                    out,
                    0
            );
            decrypted = Arrays.copyOf(out, outlen);
        }
        // -----------------------------------------------------------------------------------------------------------------
        assertThat(decrypted).isEqualTo(plain);
    }

    private static void __buffer(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
        // -------------------------------------------------------------------------------------------------------------
        cipher.init(true, params);
        final var encrypted = ByteBuffer.allocate(cipher.getOutputSize(plain.length));
        {
            final var bytes = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    ByteBuffer.wrap(plain),
                    encrypted
            );
        }
        // -------------------------------------------------------------------------------------------------------------
        encrypted.flip();
        cipher.init(false, params);
        final var decrypted = ByteBuffer.allocate(cipher.getOutputSize(encrypted.remaining()));
        {
            final var bytes = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    encrypted,
                    decrypted
            );
        }
        // -----------------------------------------------------------------------------------------------------------------
        assertThat(decrypted.flip()).isEqualTo(ByteBuffer.wrap(plain));
    }

    private static void __stream(final BufferedBlockCipher cipher, final CipherParameters params,
                                 final byte[] plain)
            throws Exception {
        // -------------------------------------------------------------------------------------------------------------
        final byte[] encrypted;
        {
            cipher.init(true, params);
            final var in = new ByteArrayInputStream(plain);
            final var out = new ByteArrayOutputStream();
            final var bytes = JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    new byte[ThreadLocalRandom.current().nextInt(128) + cipher.getBlockSize()],
                    null
            );
            assert bytes >= plain.length;
            encrypted = out.toByteArray();
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] decrypted;
        {
            cipher.init(false, params);
            final var in = new ByteArrayInputStream(encrypted);
            final var out = new ByteArrayOutputStream();
            final var bytes = JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    new byte[ThreadLocalRandom.current().nextInt(128) + cipher.getBlockSize()],
                    null
            );
            assert bytes <= encrypted.length;
            decrypted = out.toByteArray();
        }
        // -----------------------------------------------------------------------------------------------------------------
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        __array(cipher, params, plain);
        __buffer(cipher, params, plain);
        __stream(cipher, params, plain);
    }
}