package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class __OFB__TestUtils {

    public static Stream<Arguments> getKeySizeAndBitWidthArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier) {
        return keySizeStreamSupplier.get().mapToObj(ks -> {
            return __OFB__Utils.getBitWidthStream().mapToObj(bw -> {
                return Arguments.of(
                        Named.named("keySize: " + ks, ks),
                        Named.named("bitWidth: " + bw, bw)
                );
            });
        }).flatMap(Function.identity());
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        return __OFB__Utils.getBitWidthStream()
                .mapToObj(bw -> {
                    final var engine = cipherSupplier.get();
                    try {
                        return new OFBBlockCipher(engine, bw);
                    } catch (final Exception e) {
                        log.error("failed to create cipher for bitWidth: {}", bw, e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .flatMap(c -> keySizeStreamSupplier.get().mapToObj(ks -> {
                    final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
                    final var iv = _Random_TestUtils.newRandomBytes(c.getBlockSize());
                    final var params = new ParametersWithIV(new KeyParameter(key), iv);
                    return Arguments.of(
                            _BlockCipher_TestUtils.named(c),
                            _ParametersWithIV_TestUtils.named(params)
                    );
                }));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private __OFB__TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
