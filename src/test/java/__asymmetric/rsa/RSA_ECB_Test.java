package __asymmetric.rsa;

import __asymmetric._RSA_Tests;
import __symmetric._ECB_Tests;
import __symmetric._JCEProviderTest;
import _javax.security._Random_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class RSA_ECB_Test
        extends _RSA_Test {

    @DisplayName("Low-level API")
    @Nested
    class LowLevelApiTest {

        @Test
        void __() throws Exception {
        }
    }

    @DisplayName("JCE Provider")
    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static void __(final Cipher cipher, final byte[] plain, final Key key1, final Key key2)
                throws Exception {
            cipher.init(Cipher.ENCRYPT_MODE, key1);
            final var encrypted = cipher.doFinal(plain);
            cipher.init(Cipher.DECRYPT_MODE, key2);
            final var decrypted = cipher.doFinal(encrypted);
            assertThat(decrypted).isEqualTo(plain);
        }

        private static void __(final Cipher cipher, final byte[] plain, final KeyPair keyPair)
                throws Exception {
            __(cipher, plain, keyPair.getPublic(), keyPair.getPrivate());
            __(cipher, plain, keyPair.getPrivate(), keyPair.getPublic());
        }

        @DisplayName("PKCS1Padding")
        @Nested
        class PKCS1PaddingTest {

            private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
                return Stream.of("PKCS1Padding")
                        .map(p -> ALGORITHM + '/' + _ECB_Tests.MODE + '/' + p)
                        .flatMap(t -> _RSA_Tests.getKeySizeStream().mapToObj(ks -> Arguments.of(t, ks)));
            }

            private static final Map<Integer, Integer> M_LEN = new HashMap<>() {{
                put(1024, 117);
                put(2048, 245);
            }};

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
                final var mLen = M_LEN.computeIfAbsent(keySize, ks -> {
                    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.2.1
                    final var k = ks >> 3;
                    return k - 11; // mLen <= k - 11
                });
                JCEProviderTest.__(cipher, new byte[0], keyPair);
                JCEProviderTest.__(cipher, _Random_TestUtils.newRandomBytes(mLen), keyPair);
                for (int i = 0; i < 16; i++) {
                    final var plain = _Random_TestUtils.newRandomBytes(
                            ThreadLocalRandom.current().nextInt(mLen + 1)
                    );
                    JCEProviderTest.__(cipher, plain, keyPair);
                }
            }
        }

        @DisplayName("OAEPWithSHA-1AndMGF1Padding")
        @Nested
        class OAEPWithSHA_1AndMGF1PaddingTest {

            private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
                return Stream.of("OAEPWithSHA-1AndMGF1Padding")
                        .map(p -> ALGORITHM + '/' + _ECB_Tests.MODE + '/' + p)
                        .flatMap(t -> _RSA_Tests.getKeySizeStream().mapToObj(ks -> Arguments.of(t, ks)));
            }

            private static final Map<Integer, Integer> M_LEN = new HashMap<>() {{
                put(1024, 86);
                put(2048, 214);
            }};

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
                final int mLen = M_LEN.computeIfAbsent(keySize, ks -> {
                    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
                    final var k = ks >> 3;
                    final var hLen = 160 >> 3;
                    return k - (hLen << 1) - 2; // mLen <= k - 2hLen - 2
                });
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

        @DisplayName("OAEPWithSHA-256AndMGF1Padding")
        @Nested
        class OAEPWithSHA_256AndMGF1PaddingTest {

            private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
                return Stream.of("OAEPWithSHA-256AndMGF1Padding")
                        .map(p -> ALGORITHM + '/' + _ECB_Tests.MODE + '/' + p)
                        .flatMap(t -> _RSA_Tests.getKeySizeStream().mapToObj(ks -> Arguments.of(t, ks)));
            }

            private static final Map<Integer, Integer> M_LEN = new HashMap<>() {{
                put(1024, 62);
                put(2048, 190);
            }};

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
                final int mLen = M_LEN.computeIfAbsent(keySize, ks -> {
                    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
                    final var k = ks >> 3;
                    final var hLen = 256 >> 3;
                    return k - (hLen << 1) - 2; // mLen <= k - 2hLen - 2
                });
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
