package _org.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import io.github.jinahya.bouncycastle.crypto.JinahyaBufferedBlockCipherCrypto;
import io.github.jinahya.bouncycastle.crypto.JinahyaBufferedBlockCipherUtils_Test;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.bouncycastle.crypto.modes.KXTSBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public final class _BufferedBlockCipher_TestUtils {

    public static String name(final BufferedBlockCipher cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        return _BlockCipher_TestUtils.cipherName(cipher.getUnderlyingCipher());
    }

    public static <T extends BufferedBlockCipher> Named<T> named(final T cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        return Named.of(name(cipher), cipher);
    }

    public static String cipherName(final BufferedBlockCipher cipher, final BlockCipherPadding padding) {
        return _BlockCipher_TestUtils.cipherName(
                Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher(),
                padding
        );
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] plain) {
        final var adapter = new JinahyaBufferedBlockCipherCrypto(cipher, params);
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = adapter.encrypt(plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = adapter.decrypt(encrypted);
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        __(cipher, params, new byte[0]); // empty
        __(cipher, params, new byte[1]); // single-zero
        __(cipher, params, _Random_TestUtils.newRandomBytes(1)); // single-random
        __(cipher, params, _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024)));
        JinahyaBufferedBlockCipherUtils_Test.__(cipher, params);
        _BlockCipher_TestUtils.__(cipher.getUnderlyingCipher(), params);
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final File dir,
                          final File plain)
            throws IOException {
        final var adapter = new JinahyaBufferedBlockCipherCrypto(cipher, params);
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var in = new FileInputStream(plain);
             var out = new FileOutputStream(encrypted)) {
            final var bytes = adapter.encrypt(
                    in,
                    out,
                    new byte[ThreadLocalRandom.current().nextInt(cipher.getBlockSize()) + 1]
            );
            assert bytes >= 0;
            out.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var in = new FileInputStream(encrypted);
             var out = new FileOutputStream(decrypted)) {
            final var bytes = adapter.decrypt(
                    in,
                    out,
                    new byte[ThreadLocalRandom.current().nextInt(cipher.getBlockSize()) + 1]
            );
            assert bytes >= 0;
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSize(plain.length());
        assertThat(decrypted).hasSameBinaryContentAs(plain);
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params, final File dir)
            throws Exception {
        __(cipher, params, dir, File.createTempFile("tmp", null, dir)); // empty
        __(cipher, params, dir, _Random_TestUtils.createTempFileWithRandomBytesWritten(dir)); // random
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return _BlockCipher_TestUtils.getCipherAndParamsArgumentsStream()
                .flatMap(a -> {
                    final var arguments = a.get();
                    final var cipher = ((Named<BlockCipher>) arguments[0]).getPayload();
                    final var params = (CipherParameters) arguments[1];
                    return Stream.of(
                            Arguments.of(
                                    named(new CTSBlockCipher(cipher)),
                                    params
                            ),
                            Arguments.of(
                                    named(new KXTSBlockCipher(cipher)),
                                    params instanceof ParametersWithIV ? params : new ParametersWithIV(
                                            params,
                                            _Random_TestUtils.newRandomBytes(cipher.getBlockSize())
                                    )
                            )
                    );
                });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _BufferedBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
