package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class __ECB__TestUtils {

    static byte[] newRandomIv(final int blockBytes) {
        return _Random_TestUtils.newRandomBytes(blockBytes);
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return keySizeStreamSupplier.get().mapToObj(ks -> {
            final var cipher = cipherSupplier.get();
            final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
            final var params = new KeyParameter(key);
            return Arguments.of(
                    _BlockCipher_TestUtils.named(cipher),
                    _KeyParameters_TestUtils.named(params)
            );
        });
    }

    private __ECB__TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}