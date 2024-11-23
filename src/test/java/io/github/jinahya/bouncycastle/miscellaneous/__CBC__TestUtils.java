package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class __CBC__TestUtils {

    static byte[] newRandomIv(final int blockBytes) {
        return _Random_TestUtils.newRandomBytes(blockBytes);
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return keySizeStreamSupplier.get().mapToObj(ks -> {
            final var cipher = CBCBlockCipher.newInstance(cipherSupplier.get());
            final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
            final var iv = _Random_TestUtils.newRandomBytes(cipher.getUnderlyingCipher().getBlockSize());
            final var params = new ParametersWithIV(
                    new KeyParameter(key),
                    iv
            );
            return Arguments.of(
                    _BlockCipher_TestUtils.named(cipher),
                    _ParametersWithIV_TestUtils.named(params)
            );
        });
    }

    private __CBC__TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}