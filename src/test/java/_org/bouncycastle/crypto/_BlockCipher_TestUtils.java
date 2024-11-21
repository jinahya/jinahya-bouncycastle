package _org.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import io.github.jinahya.bouncycastle.crypto.JinahyaBlockCipherUtils;
import io.github.jinahya.bouncycastle.miscellaneous._AES___Constants;
import io.github.jinahya.bouncycastle.miscellaneous._SEED___Constants;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

public class _BlockCipher_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    static String cipherName(final BlockCipher cipher, final int keySize) {
        return String.format("%1$s/%2$d", cipher.getAlgorithmName(), keySize);
    }

    public static String cipherName(final BlockCipher cipher, final BlockCipherPadding padding) {
        return String.format("%1$s/%2$s", cipher.getAlgorithmName(), padding.getPaddingName());
    }

    static String keyName(final byte[] key) {
        return String.format("%1$d 0x%2$02X", key.length << 3, key[0]);
    }

    public static String paramsName(final CipherParameters parameters) {
        Objects.requireNonNull(parameters, "parameters is null");
        if (parameters instanceof KeyParameter p) {
            return _KeyParameters_TestUtils.paramsName(p);
        }
        if (parameters instanceof ParametersWithIV p) {
            return _ParametersWithIV_TestUtils.paramsName(p);
        }
        throw new RuntimeException("failed to get key from " + parameters);
    }

    public static String cipherName(final BlockCipher cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        return String.format("%1$s", cipher.getAlgorithmName());
    }

    public static <T extends BlockCipher> Named<T> named(final T cipher) {
        return Named.of(cipherName(cipher), cipher);
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return Stream.of(
                Arguments.of(
                        named(AESEngine.newInstance()),
                        new KeyParameter(_Random_TestUtils.newRandomBytes(_AES___Constants.BLOCK_BYTES))
                ),
                Arguments.of(
                        named(new SEEDEngine()),
                        new KeyParameter(_Random_TestUtils.newRandomBytes(_SEED___Constants.BLOCK_BYTES))
                )
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static void __array(final BlockCipher cipher, final CipherParameters params, final byte[] plain)
            throws IOException {
        // ----------------------------------------------------------------------------------------------------- encrypt
        {
            cipher.init(true, params);
            final var in = new ByteArrayInputStream(plain);
            final var out = new ByteArrayOutputStream();
            final var blocks = JinahyaBlockCipherUtils.processAllBlocks(
                    cipher,
                    in,
                    out,
                    new byte[cipher.getBlockSize()],
                    new byte[cipher.getBlockSize()],
                    l -> {
                    },
                    l -> {
                    }
            );
            assertThat(blocks).isEqualTo(plain.length / cipher.getBlockSize());
            final var bytes = out.toByteArray();
            if (blocks > 0) {
                assertThat(bytes.length % blocks).isZero();
            }
            assertThat(bytes.length / cipher.getBlockSize()).isEqualTo(blocks);
        }
    }

    public static void __(final BlockCipher cipher, final CipherParameters params) throws IOException {
        final var plain = new byte[ThreadLocalRandom.current().nextInt(8192)];
        __array(cipher, params, plain);
    }

    private _BlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}