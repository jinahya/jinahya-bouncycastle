package __symmetric.aes;

import __symmetric._GCM_Constants;
import __symmetric._GCM_TestUtils;
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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Path;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_GCM_Test
        extends AES__Test {

    @DisplayName("Low-level API")
    @Nested
    class LowLevelAPI_Test {

        private static Stream<Arguments> getCipherAndParamsArgumentsStream_() {
            return _GCM_TestUtils.getCipherAndParamsArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final AEADCipher cipher, final CipherParameters params) throws Exception {
            _AEADCipher_TestUtils.__(cipher, params);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final AEADCipher cipher, final CipherParameters params, @TempDir final File dir) throws Exception {
            _AEADCipher_TestUtils.__(cipher, params, dir);
        }
    }

    @DisplayName("JCE Provider")
    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static Stream<Arguments> getTransformationKeySizeAndTLenArgumentsStream() {
            return Stream.of("NoPadding")
                    .map(p -> ALGORITHM + '/' + _GCM_Constants.MODE + '/' + p)
                    .flatMap(t -> getKeySizeStream().mapToObj(ks -> {
                        return _GCM_TestUtils.getTLenStream().mapToObj(tl -> {
                            return Arguments.of(t, ks, tl);
                        });
                    })).flatMap(Function.identity());
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getTransformationKeySizeAndTLenArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key and {2}-bit tag length")
        void __(final String transformation, final int keySize, final int tLen) throws Exception {
            final var cipher = Cipher.getInstance(transformation);
            final var key = new SecretKeySpec(
                    _Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM
            );
            _Random_TestUtils.getRandomBytesStream().forEach(p -> {
                final var iv = _Random_TestUtils.newRandomBytes(BLOCK_BYTES);
                final var params = new GCMParameterSpec(tLen, iv);
                final var aad = ThreadLocalRandom.current().nextBoolean()
                        ? null
                        : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
                try {
                    _Cipher_TestUtils.__(cipher, key, params, aad, p);
                } catch (final Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getTransformationKeySizeAndTLenArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key and {2}-bit tag length")
        void __(final String transformation, final int keySize, final int tLen, @TempDir final Path dir)
                throws Exception {
            final var cipher = Cipher.getInstance(transformation);
            final var key = new SecretKeySpec(
                    _Random_TestUtils.newRandomBytes(keySize >> 3),
                    ALGORITHM
            );
            _Random_TestUtils.getRandomFileStream(dir).forEach(p -> {
                final var iv = _Random_TestUtils.newRandomBytes(BLOCK_BYTES);
                final var params = new GCMParameterSpec(tLen, iv);
                final var aad = ThreadLocalRandom.current().nextBoolean()
                        ? null
                        : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
                try {
                    _Cipher_TestUtils.__(cipher, key, params, aad, dir, p);
                } catch (final Exception e) {
                    throw new RuntimeException("failed to test with " + cipher, e);
                }
            });
        }
    }
}
