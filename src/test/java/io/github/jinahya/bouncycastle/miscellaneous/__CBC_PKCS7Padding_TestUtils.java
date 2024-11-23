package io.github.jinahya.bouncycastle.miscellaneous;

import _org.bouncycastle.crypto.paddings._PaddedBufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import _org.junit.jupiter.params.provider._Arguments_TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.params.provider.Arguments;

import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class __CBC_PKCS7Padding_TestUtils {

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        return __CBC__TestUtils.getCipherAndParamsArgumentsStream(keySizeStreamSupplier, cipherSupplier)
                .map(a -> {
                    return _Arguments_TestUtils.ofPayloadsMapped(
                            a,
                            i -> p -> switch (i) {
                                case 0 -> _PaddedBufferedBlockCipher_TestUtils.named(
                                        new PaddedBufferedBlockCipher((BlockCipher) p, new PKCS7Padding())
                                );
                                case 1 -> _ParametersWithIV_TestUtils.named((ParametersWithIV) p);
                                default -> p;
                            }
                    );
                });
    }

    private __CBC_PKCS7Padding_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}