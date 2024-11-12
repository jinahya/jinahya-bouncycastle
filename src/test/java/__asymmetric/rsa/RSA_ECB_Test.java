package __asymmetric.rsa;

import __asymmetric._RSA__Constants;
import __asymmetric._RSA__TestUtils;
import __symmetric._ECB_Constants;
import __symmetric._JCEProviderTest;
import _javax.security._Random_TestUtils;
import _javax.security._Signature_Tests;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class RSA_ECB_Test
        extends _RSA_Test {

    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException nsae) {
            throw new ExceptionInInitializerError(nsae.getMessage());
        }
    }

    @DisplayName("Low-level API")
    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getKeySizeAndParamsArgumentsStream() {
            return _RSA__TestUtils.getKeySizeStream().mapToObj(ks -> {
                return Arguments.of(ks, new RSAKeyGenerationParameters(
                        new BigInteger("10001", 16),
                        SECURE_RANDOM,
                        ks,
                        80
                ));
            });
        }

        @DisplayName("PKCS1Padding")
        @Nested
        class PKCS1Encoding_Test {

            private static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
                return _RSA__TestUtils.getKeySizeStream().mapToObj(ks -> {
                    final var params = new RSAKeyGenerationParameters(
                            new BigInteger("10001", 16),
                            SECURE_RANDOM,
                            ks,
                            80
                    );
                    final var generator = new RSAKeyPairGenerator();
                    generator.init(params);
                    final var keyPair = generator.generateKeyPair();
                    return Arguments.of(ks, keyPair);
                });
            }

            @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
            @ParameterizedTest
            void __(final int keySize, final AsymmetricCipherKeyPair keyPair) throws Exception {
                // https://github.com/anonrig/bouncycastle-implementations/blob/master/rsa.java
                // https://www.mysamplecode.com/2011/08/java-rsa-encrypt-string-using-bouncy.html
                // https://www.mysamplecode.com/2011/08/java-rsa-decrypt-string-using-bouncy.html
                final var cipher = new PKCS1Encoding(new RSAEngine());
                final var mLen = _RSA__TestUtils.mLen_RSAES_PKCS1_v1_5(keySize >> 3);
                final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(mLen + 1));
                // ---------------------------------------------------------------------------------------------------------
                cipher.init(true, keyPair.getPublic());
                final var encrypted = cipher.processBlock(plain, 0, plain.length);
                // ---------------------------------------------------------------------------------------------------------
                cipher.init(false, keyPair.getPrivate());
                final var decrypted = cipher.processBlock(encrypted, 0, encrypted.length);
                // ---------------------------------------------------------------------------------------------------------
                assertThat(decrypted).isEqualTo(plain);
            }
        }

        @DisplayName("OAEPWithSHA-1AndMGF1Padding")
        @Nested
        class OAEPWithSAH_1AndMGF1Padding_Test {

            private static final String MD_NAME = "SHA-1";

            private static final String MGF_NAME = "MGF1";

            private static final int HASH_SIZE = 160;

            private static final int H_LEN = HASH_SIZE >> 3;

            private static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
                return _RSA__TestUtils.getKeySizeStream().mapToObj(ks -> {
                    final var params = new RSAKeyGenerationParameters(
                            new BigInteger("10001", 16),
                            SECURE_RANDOM,
                            ks,
                            80
                    );
                    final var generator = new RSAKeyPairGenerator();
                    generator.init(params);
                    final var keyPair = generator.generateKeyPair();
                    return Arguments.of(ks, keyPair);
                });
            }

            @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
            @ParameterizedTest
            void __(final int keySize, final AsymmetricCipherKeyPair keyPair) throws Exception {
                // https://stackoverflow.com/a/32166210/330457
                // https://stackoverflow.com/a/3101932/330457
                final var cipher = new OAEPEncoding(new RSAEngine(), new SHA1Digest(), new SHA1Digest(), new byte[0]);
                final var mLen = _RSA__TestUtils.mLen_RSAES_OAEP(keySize >> 3, H_LEN);
                final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(mLen + 1));
                // ---------------------------------------------------------------------------------------------------------
                cipher.init(true, keyPair.getPublic());
                final var encrypted = cipher.processBlock(plain, 0, plain.length);
                // ---------------------------------------------------------------------------------------------------------
                cipher.init(false, keyPair.getPrivate());
                final var decrypted = cipher.processBlock(encrypted, 0, encrypted.length);
                // ---------------------------------------------------------------------------------------------------------
                assertThat(decrypted).isEqualTo(plain);
            }
        }

        @DisplayName("OAEPWithSHA-256AndMGF1Padding")
        @Nested
        class OAEPWithSHA_256AndMGF1Padding_Test {

            private static final int HASH_SIZE = 256;

            private static final int H_LEN = HASH_SIZE >> 3;

            private static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
                return _RSA__TestUtils.getKeySizeStream().mapToObj(ks -> {
                    final var params = new RSAKeyGenerationParameters(
                            new BigInteger("10001", 16),
                            SECURE_RANDOM,
                            ks,
                            80
                    );
                    final var generator = new RSAKeyPairGenerator();
                    generator.init(params);
                    final var keyPair = generator.generateKeyPair();
                    return Arguments.of(ks, keyPair);
                });
            }

            @MethodSource({"getKeySizeAndAsymmetricCipherKeyPairArgumentsStream"})
            @ParameterizedTest
            void __(final int keySize, final AsymmetricCipherKeyPair keyPair) throws Exception {
                // https://stackoverflow.com/a/32166210/330457
                // https://stackoverflow.com/a/3101932/330457
                final var cipher = new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA1Digest(), new byte[0]);
                final var mLen = _RSA__TestUtils.mLen_RSAES_OAEP(keySize >> 3, H_LEN);
                final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(mLen + 1));
                // ---------------------------------------------------------------------------------------------------------
                cipher.init(true, keyPair.getPublic());
                final var encrypted = cipher.processBlock(plain, 0, plain.length);
                // ---------------------------------------------------------------------------------------------------------
                cipher.init(false, keyPair.getPrivate());
                final var decrypted = cipher.processBlock(encrypted, 0, encrypted.length);
                // ---------------------------------------------------------------------------------------------------------
                assertThat(decrypted).isEqualTo(plain);
            }
        }
    }

    @DisplayName("JCE Provider")
    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static void __(final Cipher cipher, final byte[] plain, final Key key1, final Key key2)
                throws Exception {
            // ------------------------------------------------------------------------------------------------- encrypt
            cipher.init(Cipher.ENCRYPT_MODE, key1);
            final var encrypted = cipher.doFinal(plain);
            // ------------------------------------------------------------------------------------------------- decrypt
            cipher.init(Cipher.DECRYPT_MODE, key2);
            final var decrypted = cipher.doFinal(encrypted);
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
        }

        private static void __(final Cipher cipher, final byte[] plain, final KeyPair keyPair)
                throws Exception {
            __(cipher, plain, keyPair.getPublic(), keyPair.getPrivate());
            __(cipher, plain, keyPair.getPrivate(), keyPair.getPublic());
        }

        // -----------------------------------------------------------------------------------------------------------------
        @DisplayName("/ECB/PKCS1Padding")
        @Nested
        class _ECB_PKCS1Padding_Test {

            private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
                return Stream.of("PKCS1Padding")
                        .map(p -> _RSA__Constants.ALGORITHM + '/' + _ECB_Constants.MODE + '/' + p)
                        .flatMap(t -> _RSA__Constants.getKeySizeStream().mapToObj(ks -> Arguments.of(t, ks)));
            }

            @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
            @ParameterizedTest
            void __(final String transformation, final int keySize) throws Exception {
                final var cipher = Cipher.getInstance(transformation);
                final KeyPair keyPair;
                {
                    final var generator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                    generator.initialize(keySize);
                    keyPair = generator.generateKeyPair();
                }
                final var mLen = _RSA__TestUtils.mLen_RSAES_PKCS1_v1_5(keySize >> 3);
                JCEProviderTest.__(cipher, new byte[0], keyPair);
                JCEProviderTest.__(cipher, _Random_TestUtils.newRandomBytes(mLen), keyPair);
                for (int i = 0; i < 16; i++) {
                    final var plain = _Random_TestUtils.newRandomBytes(
                            ThreadLocalRandom.current().nextInt(mLen + 1)
                    );
                    JCEProviderTest.__(cipher, plain, keyPair);
                    _Signature_Tests.verifyRsa(plain, keyPair);
                }
            }
        }

        @DisplayName("/ECB/OAEPWithSHA-1AndMGF1Padding")
        @Nested
        class _ECB_OAEPWithSHA_1AndMGF1Padding_Test {

            private static final int HASH_SIZE = 160;

            private static final int H_LEN = HASH_SIZE >> 3;

            private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
                return Stream.of("OAEPWithSHA-1AndMGF1Padding")
                        .map(p -> _RSA__Constants.ALGORITHM + '/' + _ECB_Constants.MODE + '/' + p)
                        .flatMap(t -> _RSA__Constants.getKeySizeStream().mapToObj(ks -> Arguments.of(t, ks)));
            }

            @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
            @ParameterizedTest
            void __(final String transformation, final int keySize) throws Exception {
                final var cipher = Cipher.getInstance(transformation);
                final KeyPair keyPair;
                {
                    final var generator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                    generator.initialize(keySize);
                    keyPair = generator.generateKeyPair();
                }
                final int mLen = _RSA__TestUtils.mLen_RSAES_OAEP(keySize >> 3, H_LEN);
//                log.debug("hLen: {}, k: {}, mLen: {}", H_LEN, keySize >> 3, mLen);
                JCEProviderTest.__(
                        cipher,
                        new byte[0],
                        keyPair.getPublic(),
                        keyPair.getPrivate()
                );
                JCEProviderTest.__(
                        cipher,
                        _Random_TestUtils.newRandomBytes(mLen),
                        keyPair.getPublic(),
                        keyPair.getPrivate()
                );
                for (int i = 0; i < 16; i++) {
                    final var plain = _Random_TestUtils.newRandomBytes(
                            ThreadLocalRandom.current().nextInt(mLen + 1)
                    );
                    JCEProviderTest.__(
                            cipher,
                            plain,
                            keyPair.getPublic(),
                            keyPair.getPrivate()
                    );
                }
            }
        }

        @DisplayName("/ECB/OAEPWithSHA-256AndMGF1Padding")
        @Nested
        class _ECB_OAEPWithSHA_256AndMGF1Padding_Test {

            private static final int HASH_SIZE = 256;

            private static final int H_LEN = HASH_SIZE >> 3;

            private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
                return Stream.of("OAEPWithSHA-256AndMGF1Padding")
                        .map(p -> _RSA__Constants.ALGORITHM + '/' + _ECB_Constants.MODE + '/' + p)
                        .flatMap(t -> _RSA__Constants.getKeySizeStream().mapToObj(ks -> Arguments.of(t, ks)));
            }

            @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
            @ParameterizedTest
            void __(final String transformation, final int keySize) throws Exception {
                final var cipher = Cipher.getInstance(transformation);
                final KeyPair keyPair;
                {
                    final var generator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
                    generator.initialize(keySize);
                    keyPair = generator.generateKeyPair();
                }
                final int mLen = _RSA__TestUtils.mLen_RSAES_OAEP(keySize >> 3, H_LEN);
//                log.debug("hLen: {}, k: {}, mLen: {}", H_LEN, keySize >> 3, mLen);
                JCEProviderTest.__(
                        cipher,
                        new byte[0],
                        keyPair.getPublic(),
                        keyPair.getPrivate()
                );
                JCEProviderTest.__(
                        cipher,
                        _Random_TestUtils.newRandomBytes(mLen),
                        keyPair.getPublic(),
                        keyPair.getPrivate()
                );
                for (int i = 0; i < 16; i++) {
                    final var plain = _Random_TestUtils.newRandomBytes(
                            ThreadLocalRandom.current().nextInt(mLen + 1)
                    );
                    JCEProviderTest.__(
                            cipher,
                            plain,
                            keyPair.getPublic(),
                            keyPair.getPrivate()
                    );
                }
            }
        }
    }
}
