package io.github.jinahya.util.nist;

import _javax.crypto._Cipher_TestUtils;
import _javax.security._Random_TestUtils;
import _org.bouncycastle.jce.provider._BouncyCastleProvider_TestUtils;
import io.github.jinahya.util._ECB_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import io.github.jinahya.util.bouncycastle.crypto.paddings._BlockCipherPaddingTestUtils;
import io.github.jinahya.util.bouncycastle.crypto.params._KeyParametersTestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class AES_ECB_Test
        extends AES__Test {

    private static Stream<Arguments> getKeySizeAndPaddingArgumentsStream() {
        return getKeySizeStream().mapToObj(ks -> {
            return _BlockCipherPaddingTestUtils.getBlockCipherPaddingStream()
                    .map(p -> Arguments.of(
                            Named.of("keySize: " + ks, ks),
                            Named.of("padding: " + p.getPaddingName(), p)
                    ));
        }).flatMap(Function.identity());
    }

    @MethodSource({"getKeySizeAndPaddingArgumentsStream"})
    @ParameterizedTest
    void __(final int keySize, final BlockCipherPadding padding) throws InvalidCipherTextException {
        final var cipher = new PaddedBufferedBlockCipher(AESEngine.newInstance(), padding);
        final var key = _Random_TestUtils.newRandomBytes(keySize >>> 3);
        assert key.length == 16 || key.length == 24 || key.length == 32;
        final var params = new KeyParameter(key);
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        var encrypted = new byte[cipher.getOutputSize(plain.length)];
        {
            final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
            final var finalized = cipher.doFinal(encrypted, processed);
            encrypted = Arrays.copyOf(encrypted, (processed + finalized));
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        byte[] decrypted = new byte[cipher.getOutputSize(encrypted.length)];
        {
            final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
            final var finalized = cipher.doFinal(decrypted, processed);
            decrypted = Arrays.copyOf(decrypted, (processed + finalized));
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
    }

    @MethodSource({"getKeySizeAndPaddingArgumentsStream"})
    @ParameterizedTest
    void __(final int keySize, final BlockCipherPadding padding, @TempDir final Path dir) throws Exception {
        final var cipher = new PaddedBufferedBlockCipher(AESEngine.newInstance(), padding);
        final var key = _Random_TestUtils.newRandomBytes(keySize >>> 3);
        assert key.length == 16 || key.length == 24 || key.length == 32;
        final var params = new KeyParameter(key);
        final var plain = Files.createTempFile(dir, null, null);
        {
            final var bytes = new byte[ThreadLocalRandom.current().nextInt(1024)];
            ThreadLocalRandom.current().nextBytes(bytes);
            Files.write(plain, bytes);
        }
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = Files.createTempFile(dir, null, null);
        try (var out = new CipherOutputStream(new FileOutputStream(encrypted.toFile()), cipher)) {
            Files.copy(plain, out);
            out.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = Files.createTempFile(dir, null, null);
        cipher.init(false, params);
        try (var in = new CipherInputStream(new FileInputStream(encrypted.toFile()), cipher)) {
            Files.copy(in, decrypted, StandardCopyOption.REPLACE_EXISTING);
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSameBinaryContentAs(plain);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return _ECB_TestUtils.getArgumentsStream(
                AES__Test::getKeySizeStream,
                AESEngine::newInstance
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getCipherAndParamsArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        _BufferedBlockCipher_TestUtils.__(cipher, params);
    }

    @MethodSource({"getCipherAndParamsArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        _BufferedBlockCipher_TestUtils.__(cipher, params, dir);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static IntStream getKeySizeStream_() {
        return getKeySizeStream();
    }

    @DisplayName("BC://AES/ECB/PKCS5Padding")
    @MethodSource({"getKeySizeStream_"})
    @ParameterizedTest
    void __(final int keySize) throws Throwable {
        _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
            final var transformation = ALGORITHM + '/' + _ECB_TestUtils.MODE + "/PKCS5Padding";
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            _Cipher_TestUtils.__(cipher, key);
            return null;
        });
    }

    @DisplayName("BC://AES/ECB/PKCS5Padding")
    @MethodSource({"getKeySizeStream_"})
    @ParameterizedTest
    void __(final int keySize, @TempDir final Path dir) throws Throwable {
        _BouncyCastleProvider_TestUtils.callForBouncyCastleProvider(() -> {
            final var transformation = ALGORITHM + '/' + _ECB_TestUtils.MODE + "/PKCS5Padding";
            final var cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
            final var key = new SecretKeySpec(
                    _KeyParametersTestUtils.newRandomKey(null, keySize),
                    ALGORITHM
            );
            _Cipher_TestUtils.__(cipher, key, dir);
            return null;
        });
    }
}
