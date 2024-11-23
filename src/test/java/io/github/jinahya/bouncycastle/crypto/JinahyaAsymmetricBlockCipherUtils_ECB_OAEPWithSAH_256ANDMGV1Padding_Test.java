package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import io.github.jinahya.bouncycastle.miscellaneous._RSA___Constants;
import io.github.jinahya.bouncycastle.miscellaneous._RSA___TestUtils;
import io.github.jinahya.bouncycastle.miscellaneous._RSA___Utils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
@Slf4j
class JinahyaAsymmetricBlockCipherUtils_ECB_OAEPWithSAH_256ANDMGV1Padding_Test {

    @DisplayName("processBlock(cipher, in)")
    @Nested
    class ProcessBlock_Array_Test {

        private static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
            return _RSA___TestUtils.getKeySizeAndAsymmetricCipherKeyPairArgumentsStream();
        }

        @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key")
        void __(final int keySize, final AsymmetricCipherKeyPair keyPair) throws Exception {
            // https://stackoverflow.com/a/32166210/330457
            // https://stackoverflow.com/a/3101932/330457
            final var cipher = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA1Digest(), new byte[0]);
            final var mLen = _RSA___Utils.max_mLen_RSAES_OAEP(keySize >> 3, _RSA___Constants.H_LEN_SHA256);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(mLen + 1));
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(true, keyPair.getPublic());
            assertThat(cipher.getInputBlockSize()).isEqualTo(mLen);
            final byte[] encrypted;
            {
                final byte[] out = new byte[cipher.getOutputBlockSize()];
                final var outlen = JinahyaAsymmetricBlockCipherUtils.processBlock(
                        cipher,
                        plain,
                        0,
                        plain.length,
                        out,
                        0
                );
                encrypted = Arrays.copyOf(out, outlen);
            }
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(false, keyPair.getPrivate());
            assertThat(cipher.getOutputBlockSize()).isEqualTo(mLen);
            final byte[] decrypted;
            {
                final byte[] out = new byte[cipher.getOutputBlockSize()];
                final var outlen = JinahyaAsymmetricBlockCipherUtils.processBlock(
                        cipher,
                        encrypted,
                        0,
                        encrypted.length,
                        out,
                        0
                );
                decrypted = Arrays.copyOf(out, outlen);
            }
            // ---------------------------------------------------------------------------------------------------------
            assertThat(decrypted).isEqualTo(plain);
        }
    }

    @DisplayName("processBlock(cipher, input)")
    @Nested
    class ProcessBlock_Buffer_Test {

        private static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
            return _RSA___TestUtils.getKeySizeAndAsymmetricCipherKeyPairArgumentsStream();
        }

        @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key")
        void __RSA_ECB_OAEPWithSHA_256AndMGF1Padding(final int keySize, final AsymmetricCipherKeyPair keyPair)
                throws Exception {
            // https://stackoverflow.com/a/32166210/330457
            // https://stackoverflow.com/a/3101932/330457
            final var hash = new SHA256Digest();
            final var cipher = new OAEPEncoding(new RSAEngine(), hash, new SHA1Digest(), new byte[0]);
            final var mLen = _RSA___Utils.max_mLen_RSAES_OAEP(keySize >> 3, hash);
            final var plain = ByteBuffer.wrap(
                    _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(mLen + 1))
            );
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(true, keyPair.getPublic());
            assertThat(cipher.getInputBlockSize()).isEqualTo(mLen);
            final var encrypted = ByteBuffer.allocate(cipher.getOutputBlockSize());
            {
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processBlock(
                        cipher,
                        plain,
                        encrypted
                );
                assert bytes >= plain.position();
            }
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(false, keyPair.getPrivate());
            assertThat(cipher.getOutputBlockSize()).isEqualTo(mLen);
            final var decrypted = ByteBuffer.allocate(cipher.getOutputBlockSize());
            {
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processBlock(
                        cipher,
                        encrypted.flip(),
                        decrypted
                );
                assert bytes <= encrypted.position();
            }
            // ---------------------------------------------------------------------------------------------------------
            assertThat(decrypted.flip()).isEqualTo(plain.flip());
        }
    }

    @DisplayName("processAllBytes(cipher, in, out, inbuf, outbuf)")
    @Nested
    class ProcessAllBytes_Test {

        private static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
            return _RSA___TestUtils.getKeySizeAndAsymmetricCipherKeyPairArgumentsStream();
        }

        @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key")
        void __RSA_ECB_OAEPWithSHA_256AndMGF1Padding(final int keySize, final AsymmetricCipherKeyPair keyPair)
                throws Exception {
            // https://stackoverflow.com/a/32166210/330457
            // https://stackoverflow.com/a/3101932/330457
            final var hash = new SHA256Digest();
            final var cipher = new OAEPEncoding(new RSAEngine(), hash, new SHA1Digest(), new byte[0]);
            final var mLen = _RSA___Utils.max_mLen_RSAES_OAEP(keySize >> 3, hash);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            final var baos = new ByteArrayOutputStream();
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(true, keyPair.getPublic());
            assertThat(cipher.getInputBlockSize()).isEqualTo(mLen);
            final byte[] encrypted;
            {
                final var inputBlockSize = cipher.getInputBlockSize();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(inputBlockSize) + inputBlockSize];
                final var outputBlockSize = cipher.getOutputBlockSize();
                final var outbuf = new byte[ThreadLocalRandom.current().nextInt(outputBlockSize) + outputBlockSize];
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processAllBytes(
                        cipher,
                        new ByteArrayInputStream(plain),
                        baos,
                        inbuf,
                        outbuf,
                        l -> {
                        },
                        l -> {
                        }
                );
                assert bytes >= plain.length;
                encrypted = baos.toByteArray();
                baos.reset();
            }
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(false, keyPair.getPrivate());
            assertThat(cipher.getOutputBlockSize()).isEqualTo(mLen);
            final byte[] decrypted;
            {
                final var inputBlockSize = cipher.getInputBlockSize();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(inputBlockSize) + inputBlockSize];
                final var outputBlockSize = cipher.getOutputBlockSize();
                final var outbuf = new byte[ThreadLocalRandom.current().nextInt(outputBlockSize) + outputBlockSize];
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processAllBytes(
                        cipher,
                        new ByteArrayInputStream(encrypted),
                        baos,
                        inbuf,
                        outbuf,
                        l -> {
                        },
                        l -> {
                        }
                );
                assert bytes <= encrypted.length;
                decrypted = baos.toByteArray();
            }
            // ---------------------------------------------------------------------------------------------------------
            assertThat(decrypted).isEqualTo(plain);
        }
    }
}