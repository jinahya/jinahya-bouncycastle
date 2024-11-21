package __symmetric.seed;

import __symmetric._ECB_TestUtils;
import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import _org.bouncycastle.jce.provider._BouncyCastleProvider_TestUtils;
import io.github.jinahya.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import io.github.jinahya.bouncycastle.miscellaneous.__ECB__Constants;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Path;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
class SEED_ECB_Test
        extends SEED__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _ECB_TestUtils.getCipherAndParamsArgumentsStream(
                SEEDEngine::new,
                SEED__Test::getKeySizeStream
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        _BufferedBlockCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _BufferedBlockCipher_TestUtils.__(cipher, params, dir);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static IntStream getKeySizeStream_() {
        return getKeySizeStream();
    }

    @DisplayName("SEED/ECB/PKCS5Padding")
    @MethodSource({"getKeySizeStream_"})
    @ParameterizedTest
    void __(final int keySize) throws Exception {
        _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
            JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
            final var transformation = ALGORITHM + '/' + __ECB__Constants.MODE + "/PKCS5Padding";
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(
                    _Random_TestUtils.newRandomBytes(keySize >> 3),
                    ALGORITHM
            );
            _Cipher_TestUtils.__(cipher, key, null, (byte[]) null);
            return null;
        });
    }

    @DisplayName("SEED/ECB/PKCS5Padding")
    @MethodSource({"getKeySizeStream_"})
    @ParameterizedTest
    void __(final int keySize, @TempDir final Path dir) throws Exception {
        _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
            JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
            final var transformation = ALGORITHM + '/' + __ECB__Constants.MODE + "/PKCS5Padding";
            final var cipher = Cipher.getInstance(
                    transformation,
                    JinahyaBouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME
            );
            final var key = new SecretKeySpec(
                    _Random_TestUtils.newRandomBytes(keySize >> 3),
                    ALGORITHM
            );
            _Cipher_TestUtils.__(cipher, key, null, (byte[]) null, dir);
            return null;
        });
    }
}
