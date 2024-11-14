package io.github.jinahya.bouncycastle.crypto;

import __asymmetric._RSA__TestUtils;
import _javax.security._Random_TestUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class JinahyaAsymmetricBlockCipherUtilsTest {

    @DisplayName("processBytes(cipher, in, inoff, inlen, out, outoff)")
    @Nested
    class ProcessBytes_Array_Test {

        private static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
            return _RSA__TestUtils.getKeySizeAndAsymmetricCipherKeyPairArgumentsStream();
        }

        @DisplayName("RSA/ECB/PKCS1Padding")
        @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key")
        void __RSA_ECB_PKCS1Padding(final int keySize, final AsymmetricCipherKeyPair keyPair) throws Exception {
            // https://github.com/anonrig/bouncycastle-implementations/blob/master/rsa.java
            // https://www.mysamplecode.com/2011/08/java-rsa-encrypt-string-using-bouncy.html
            // https://www.mysamplecode.com/2011/08/java-rsa-decrypt-string-using-bouncy.html
            final var cipher = new PKCS1Encoding(new RSAEngine());
//            final var mLen = _RSA__TestUtils.mLen_RSAES_PKCS1_v1_5(keySize >> 3);
//            final var plain = _Random_TestUtils.newRandomBytes(mLen + 1);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8291));
            // ---------------------------------------------------------------------------------------------------------
            final byte[] encrypted;
            {
                cipher.init(true, keyPair.getPublic());
                final var out = new byte[JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, plain.length)];
                final var outlen = JinahyaAsymmetricBlockCipherUtils.processBytes(
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
            final byte[] decrypted;
            {
                cipher.init(false, keyPair.getPrivate());
                final var out = new byte[JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, encrypted.length)];
                final var outlen = JinahyaAsymmetricBlockCipherUtils.processBytes(
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

        @DisplayName("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key")
        void __RSA_ECB_OAEPWithSHA_1AndMGF1Padding(final int keySize, final AsymmetricCipherKeyPair keyPair)
                throws Exception {
            // https://stackoverflow.com/a/32166210/330457
            // https://stackoverflow.com/a/3101932/330457
            final var cipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest(), new SHA1Digest(), new byte[0]);
            final var mLen = _RSA__TestUtils.mLen_RSAES_PKCS1_v1_5(keySize >> 3);
            final var plain = _Random_TestUtils.newRandomBytes(mLen + 1);
            // ---------------------------------------------------------------------------------------------------------
            final byte[] encrypted;
            {
                cipher.init(true, keyPair.getPublic());
                final var out = new byte[JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, plain.length)];
                final var outlen = JinahyaAsymmetricBlockCipherUtils.processBytes(
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
            final byte[] decrypted;
            {
                cipher.init(false, keyPair.getPrivate());
                final var out = new byte[JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, encrypted.length)];
                final var outlen = JinahyaAsymmetricBlockCipherUtils.processBytes(
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

        @DisplayName("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key")
        void __RSA_ECB_OAEPWithSHA_256AndMGF1Padding(final int keySize, final AsymmetricCipherKeyPair keyPair)
                throws Exception {
            // https://stackoverflow.com/a/32166210/330457
            // https://stackoverflow.com/a/3101932/330457
            final var cipher = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA1Digest(), new byte[0]);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8291));
            // ---------------------------------------------------------------------------------------------------------
            final byte[] encrypted;
            {
                cipher.init(true, keyPair.getPublic());
                final var out = new byte[JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, plain.length)];
                final var outlen = JinahyaAsymmetricBlockCipherUtils.processBytes(
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
            final byte[] decrypted;
            {
                cipher.init(false, keyPair.getPrivate());
                final var out = new byte[JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, encrypted.length)];
                final var outlen = JinahyaAsymmetricBlockCipherUtils.processBytes(
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

    @DisplayName("processBytes(cipher, input, output)")
    @Nested
    class ProcessBytes_Buffer_Test {

        private static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
            return _RSA__TestUtils.getKeySizeAndAsymmetricCipherKeyPairArgumentsStream();
        }

        @DisplayName("RSA/ECB/PKCS1Padding")
        @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key")
        void __RSA_ECB_PKCS1Padding(final int keySize, final AsymmetricCipherKeyPair keyPair) throws Exception {
            // https://github.com/anonrig/bouncycastle-implementations/blob/master/rsa.java
            // https://www.mysamplecode.com/2011/08/java-rsa-encrypt-string-using-bouncy.html
            // https://www.mysamplecode.com/2011/08/java-rsa-decrypt-string-using-bouncy.html
            final var cipher = new PKCS1Encoding(new RSAEngine());
            final var plain = ByteBuffer.wrap(
                    _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8291)));
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(true, keyPair.getPublic());
            final var encrypted = ByteBuffer.allocate(
                    JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, plain.remaining())
            );
            {
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processBytes(
                        cipher,
                        plain,
                        encrypted
                );
                assertThat(bytes).isGreaterThanOrEqualTo(plain.capacity());
            }
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(false, keyPair.getPrivate());
            final var decrypted = ByteBuffer.allocate(
                    JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, encrypted.flip().remaining())
            );
            {
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processBytes(
                        cipher,
                        encrypted,
                        decrypted
                );
                assertThat(bytes).isLessThanOrEqualTo(encrypted.position());
            }
            // ---------------------------------------------------------------------------------------------------------
            assertThat(decrypted.flip()).isEqualTo(plain.flip());
        }

        @DisplayName("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
        @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key")
        void __RSA_ECB_OAEPWithSHA_1AndMGF1Padding(final int keySize, final AsymmetricCipherKeyPair keyPair)
                throws Exception {
            // https://stackoverflow.com/a/32166210/330457
            // https://stackoverflow.com/a/3101932/330457
            final var cipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest(), new SHA1Digest(), new byte[0]);
            final var mLen = _RSA__TestUtils.mLen_RSAES_PKCS1_v1_5(keySize >> 3);
            final var plain = ByteBuffer.wrap(
                    _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8291)));
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(true, keyPair.getPublic());
            final var encrypted = ByteBuffer.allocate(
                    JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, plain.remaining())
            );
            {
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processBytes(
                        cipher,
                        plain,
                        encrypted
                );
                assertThat(bytes).isGreaterThanOrEqualTo(plain.capacity());
            }
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(false, keyPair.getPrivate());
            final var decrypted = ByteBuffer.allocate(
                    JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, encrypted.flip().remaining())
            );
            {
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processBytes(
                        cipher,
                        encrypted,
                        decrypted
                );
                assertThat(bytes).isLessThanOrEqualTo(encrypted.position());
            }
            // ---------------------------------------------------------------------------------------------------------
            assertThat(decrypted.flip()).isEqualTo(plain.flip());
        }

        @DisplayName("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0}-bit key")
        void __RSA_ECB_OAEPWithSHA_256AndMGF1Padding(final int keySize, final AsymmetricCipherKeyPair keyPair)
                throws Exception {
            // https://stackoverflow.com/a/32166210/330457
            // https://stackoverflow.com/a/3101932/330457
            final var cipher = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA1Digest(), new byte[0]);
            final var plain = ByteBuffer.wrap(
                    _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8291)));
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(true, keyPair.getPublic());
            final var encrypted = ByteBuffer.allocate(
                    JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, plain.remaining())
            );
            {
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processBytes(
                        cipher,
                        plain,
                        encrypted
                );
                assertThat(bytes).isGreaterThanOrEqualTo(plain.capacity());
            }
            // ---------------------------------------------------------------------------------------------------------
            cipher.init(false, keyPair.getPrivate());
            final var decrypted = ByteBuffer.allocate(
                    JinahyaAsymmetricBlockCipherUtils.getOutLen(cipher, encrypted.flip().remaining())
            );
            {
                final var bytes = JinahyaAsymmetricBlockCipherUtils.processBytes(
                        cipher,
                        encrypted,
                        decrypted
                );
                assertThat(bytes).isLessThanOrEqualTo(encrypted.position());
            }
            // ---------------------------------------------------------------------------------------------------------
            assertThat(decrypted.flip()).isEqualTo(plain.flip());
        }
    }
}