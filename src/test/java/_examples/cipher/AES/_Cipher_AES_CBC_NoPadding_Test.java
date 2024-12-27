package _examples.cipher.AES;

import _examples.cipher._Cipher____Test;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName(_Cipher_AES_CBC_NoPadding_Test.TRANSFORMATION)
@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
@SuppressWarnings({
        "java:S3577" // Test classes should comply with a naming convention
})
class _Cipher_AES_CBC_NoPadding_Test
        extends _Cipher_AES___Test {

    private static final String MODE = "CBC";

    private static final String PADDING = "NoPadding";

    static final String TRANSFORMATION = _Cipher_AES___Test.ALGORITHM + '/' + MODE + '/' + PADDING;

    private static Stream<Arguments> getCipherKeyAndParamsArgumentsStream() {
        return _Cipher____Test.PROVIDER_NAME_LIST.stream()
                .flatMap(pn -> _Cipher_AES___Test.KEY_SIZES.stream().map(ks -> {
                    final Cipher cipher;
                    try {
                        cipher = _Cipher____Test.getCipherInstance(TRANSFORMATION, pn);
                    } catch (Exception e) {
                        throw new RuntimeException("failed to get cipher for '" + TRANSFORMATION + "'", e);
                    }
                    assertThat(cipher.getBlockSize()).isEqualTo(_Cipher_AES___Test.BLOCK_BYTES);
                    assertThat(cipher.getAlgorithm()).isEqualTo(TRANSFORMATION);
                    final Key key;
                    {
                        final var keyBytes = new byte[ks >> 3];
                        ThreadLocalRandom.current().nextBytes(keyBytes);
                        key = new SecretKeySpec(keyBytes, _Cipher_AES___Test.ALGORITHM);
                    }
                    final AlgorithmParameterSpec params;
                    {
                        final var iv = new byte[_Cipher_AES___Test.BLOCK_BYTES];
                        ThreadLocalRandom.current().nextBytes(iv);
                        params = new IvParameterSpec(iv);
                    }
                    return Arguments.of(
                            Named.of(cipher.getProvider().getName() + ' ' + cipher.getAlgorithm(), cipher),
                            Named.of(Integer.toString(key.getEncoded().length << 3), key),
                            Named.of(Integer.toString(((IvParameterSpec) params).getIV().length), params)
                    );
                }));
    }

    @MethodSource({"getCipherKeyAndParamsArgumentsStream"})
    @ParameterizedTest
    void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params) throws Exception {
        // ------------------------------------------------------------------------------------------------------- given
        final var plain = new byte[ThreadLocalRandom.current()
                .nextInt(8) * _Cipher_AES___Test.BLOCK_BYTES]; // NoPadding!!!
        ThreadLocalRandom.current().nextBytes(plain);
        log.debug("plain.length: {} (% BLOCK_BYTES = {})", plain.length,
                  (plain.length % _Cipher_AES___Test.BLOCK_BYTES));
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        final var encrypted = cipher.doFinal(plain);
        log.debug("encrypted.length: {} (% BLOCK_BYTES = {})", encrypted.length,
                  (encrypted.length % _Cipher_AES___Test.BLOCK_BYTES));
        assertThat(encrypted).hasSameSizeAs(plain); // NoPadding!!!
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        final var decrypted = cipher.doFinal(encrypted);
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
    }

    @MethodSource({"getCipherKeyAndParamsArgumentsStream"})
    @ParameterizedTest
    void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params, @TempDir final File tempDir)
            throws Exception {
        // ------------------------------------------------------------------------------------------------------- given
        final var plain = File.createTempFile("tmp", null, tempDir);
        try (var output = new FileOutputStream(plain)) {
            final var count = ThreadLocalRandom.current().nextInt(128);
            for (int i = 0; i < count; i++) {
                final var bytes = new byte[_Cipher_AES___Test.BLOCK_BYTES];
                ThreadLocalRandom.current().nextBytes(bytes);
                output.write(bytes);
            }
            output.flush();
        }
        log.debug("plain.length: {} (% BLOCK_BYTES = {})", plain.length(),
                  (plain.length() % _Cipher_AES___Test.BLOCK_BYTES));
        Assertions.assertThat(plain.length() % _Cipher_AES___Test.BLOCK_BYTES)
                .isZero(); // NoPadding!!!
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        final var encrypted = File.createTempFile("tmp", null, tempDir);
        try (var input = new FileInputStream(plain);
             final var output = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
            final var buffer = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
            for (int r; (r = input.read(buffer)) != -1; ) {
                output.write(buffer, 0, r);
            }
            output.flush();
        }
        log.debug("encrypted.length: {} (% BLOCK_BYTES = {})", encrypted.length(),
                  (encrypted.length() % _Cipher_AES___Test.BLOCK_BYTES));
        assertThat(encrypted).hasSize(plain.length());
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        final var decrypted = File.createTempFile("tmp", null, tempDir);
        try (var input = new CipherInputStream(new FileInputStream(encrypted), cipher);
             final var output = new FileOutputStream(decrypted)) {
            final var buffer = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
            for (int r; (r = input.read(buffer)) != -1; ) {
                output.write(buffer, 0, r);
            }
            output.flush();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSize(plain.length()).hasSameBinaryContentAs(plain);
    }
}
