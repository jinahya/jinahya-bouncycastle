package __symmetric.aes;

import __symmetric._JCEProviderTest;
import __symmetric._OFB_Tests;
import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._StreamCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
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
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_OFB_Test
        extends AES__Test {

    @DisplayName("Low-level API")
    @Nested
    class LowLevelApiTest {

        private static Stream<Arguments> getCipherAndParamsArgumentsStream_() {
            return _OFB_Tests.getCipherAndParamsArgumentsStream(
                    AES__Test::getKeySizeStream,
                    AESEngine::newInstance
            );
        }

        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final StreamCipher cipher, final CipherParameters params) {
            _StreamCipher_TestUtils.__(cipher, params);
        }

        @MethodSource({"getCipherAndParamsArgumentsStream_"})
        @ParameterizedTest
        void __(final StreamBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
                throws Exception {
            _StreamCipher_TestUtils.__(cipher, params, dir);
        }
    }

    @DisplayName("JCE Provider")
    @Nested
    class JCEProviderTest
            extends _JCEProviderTest {

        private static Stream<Arguments> getTransformationAndKeySizeArgumentsStream() {
            return Stream.of("NoPadding")
                    .map(p -> ALGORITHM + '/' + _OFB_Tests.MODE + '/' + p)
                    .flatMap(t -> getKeySizeStream().mapToObj(ks -> {
                        return Arguments.of(t, ks);
                    }));
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] transformation: {0}, keySize: {1}")
        void __(final String transformation, final int keySize) throws Exception {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get cipher for '{}'", transformation, nsae);
                return;
            }
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getTransformationAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] transformation: {0}, keySize: {1}, ")
        void __(final String transformation, final int keySize, @TempDir final Path dir) throws Exception {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get cipher for '{}'", transformation, nsae);
                return;
            }
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null, dir);
        }

        private static Stream<Arguments> getTransformationWithBitWidthAndKeySizeArgumentsStream() {
            return _OFB_Tests.getBitWidthStream()
                    .mapToObj(_OFB_Tests::mode)
                    .flatMap(m -> {
                        return Stream.of("NoPadding")
                                .map(p -> ALGORITHM + '/' + m + '/' + p);
                    })
                    .flatMap(t -> getKeySizeStream().mapToObj(ks -> {
                        return Arguments.of(t, ks);
                    }));
        }

        @DisplayName("encrypt/decrypt bytes")
        @MethodSource({"getTransformationWithBitWidthAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __bitWidth(final String transformation, final int keySize) throws Exception {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get cipher for '{}'", transformation, nsae);
                return;
            }
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null);
        }

        @DisplayName("encrypt/decrypt file")
        @MethodSource({"getTransformationWithBitWidthAndKeySizeArgumentsStream"})
        @ParameterizedTest(name = "[{index}] {0} with {1}-bit key")
        void __bitWidth(final String transformation, final int keySize, @TempDir final Path dir) throws Exception {
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get cipher for '{}'", transformation, nsae);
                return;
            }
            final var key = new SecretKeySpec(_Random_TestUtils.newRandomBytes(keySize >> 3), ALGORITHM);
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, null, dir);
        }
    }
}
