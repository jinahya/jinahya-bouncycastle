package io.github.jinahya.util.nist;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.jce.provider._BouncyCastleProvider_TestUtils;
import _org.junit.jupiter.params.provider._Arguments_TestUtils;
import io.github.jinahya.util._CFB_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._StreamCipher_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._ParametersWithIVTestUtils;
import io.github.jinahya.util.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Named;
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
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_CFB_Test
        extends AES__Test {

    private static Stream<Arguments> getArgumentsStream() {
        return _CFB_TestUtils.getBitWidthStream().mapToObj(bw -> {
            final var engine = AESEngine.newInstance();
            try {
                return CFBBlockCipher.newInstance(engine, bw);
            } catch (final Exception e) {
                log.error("failed to create a new cipher for bit width: {}", bw);
                return null;
            }
        }).filter(Objects::nonNull).flatMap(c -> getKeySizeStream().mapToObj(ks -> {
            final var params = _ParametersWithIVTestUtils.newRandomInstanceOfParametersWithIV(null, ks, c);
            return _Arguments_TestUtils.argumentsOf(c, params);
        }));
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params) throws Exception {
        _StreamCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final StreamCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _StreamCipher_TestUtils.__(cipher, params, dir);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static Stream<Arguments> getKeySizeAndBitWidthArgumentsStream() {
        return _CFB_TestUtils.getBitWidthStream().mapToObj(bw -> {
            return getKeySizeStream()
                    .mapToObj(ks -> Arguments.of(
                            Named.of("bitWidth", bw),
                            Named.of("keySize", ks)
                    ));
        }).flatMap(Function.identity());
    }

    @DisplayName("AES/CFB<W>/NoPadding")
    @MethodSource({"getKeySizeAndBitWidthArgumentsStream"})
    @ParameterizedTest
    void __(final int bitWidth, final int keySize) throws Throwable {
        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
            final var transformation = ALGORITHM + '/' + _CFB_TestUtils.mode(bitWidth) + "/NoPadding";
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(
                        transformation,
                        JinahyaBouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME
                );
            } catch (final NoSuchAlgorithmException naae) {
                log.error("no such algorithm: {}", transformation);
                return null;
            }
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params);
            return null;
        });
    }

    @DisplayName("AES/CFB<W>/NoPadding")
    @MethodSource({"getKeySizeAndBitWidthArgumentsStream"})
    @ParameterizedTest
    void __(final int bitWidth, final int keySize, @TempDir final Path dir) throws Throwable {
        _BouncyCastleProvider_TestUtils.callWithinBouncyCastleProvider(() -> {
            final var transformation = ALGORITHM + '/' + _CFB_TestUtils.mode(bitWidth) + "/NoPadding";
            final Cipher cipher;
            try {
                cipher = Cipher.getInstance(
                        transformation,
                        JinahyaBouncyCastleProviderUtils.BOUNCY_CASTLE_PROVIDER_NAME
                );
            } catch (final NoSuchAlgorithmException naae) {
                log.error("no such algorithm: {}", transformation);
                return null;
            }
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            final var params = new IvParameterSpec(_Random_TestUtils.newRandomBytes(BLOCK_BYTES));
            _Cipher_TestUtils.__(cipher, key, params, dir);
            return null;
        });
    }
}
