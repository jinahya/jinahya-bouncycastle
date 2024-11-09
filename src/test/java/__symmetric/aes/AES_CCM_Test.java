package __symmetric.aes;

import __symmetric._CCM_Tests;
import __symmetric._JCEProviderTest;
import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.modes._AEADCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Path;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_CCM_Test
        extends AES__Test {

    @DisplayName("Low-level API")
    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return _CCM_Tests.getCipherAndParamsArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final AEADCipher cipher, final CipherParameters params) {
            _AEADCipher_TestUtils.__(cipher, params);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getCipherAndParamsArgumentsStream"})
        @ParameterizedTest
        void __(final AEADCipher cipher, final CipherParameters params, @TempDir final File dir) throws Exception {
            _AEADCipher_TestUtils.__(cipher, params, dir);
        }
    }

    @DisplayName("JCE Provider")
    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
            return Stream.of("NoPadding")
                    .map(p -> ALGORITHM + '/' + _CCM_Tests.MODE + '/' + p)
                    .flatMap(t -> getKeySizeStream().mapToObj(ks -> Arguments.of(t, ks)));
        }

        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final String transformation, final int keySize) throws Exception {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_CCM_Tests.newBouncyCastleNonce());
            _Cipher_TestUtils.__(cipher, key, params, null);
        }

        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __(final String transformation, final int keySize, @TempDir final Path dir) throws Exception {
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_CCM_Tests.newBouncyCastleNonce());
            _Cipher_TestUtils.__(cipher, key, params, null, dir);
        }
    }
}
