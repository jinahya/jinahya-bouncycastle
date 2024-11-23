package io.github.jinahya.bouncycastle.miscellaneous;

import _org.bouncycastle.crypto.paddings._PaddedBufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import _org.junit.jupiter.params.provider._Arguments_TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.params.provider.Arguments;

import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class __ECB_PKCS7Padding_TestUtils {

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        return __ECB__TestUtils.getCipherAndParamsArgumentsStream(keySizeStreamSupplier, cipherSupplier)
                .map(a -> {
                    return _Arguments_TestUtils.ofPayloadsMapped(
                            a,
                            i -> p -> switch (i) {
                                case 0 -> _PaddedBufferedBlockCipher_TestUtils.named(
                                        new PaddedBufferedBlockCipher((BlockCipher) p)
                                );
                                case 1 -> _KeyParameters_TestUtils.named((KeyParameter) p);
                                default -> p;
                            }
                    );
                });
    }

    private __ECB_PKCS7Padding_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}