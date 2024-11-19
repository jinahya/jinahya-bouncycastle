package __symmetric;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import io.github.jinahya.bouncycastle.crypto._BlockCipher_TestUtils;
import io.github.jinahya.bouncycastle.miscellaneous.__CFB__Constants;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _CFB_TestUtils {

    public static IntStream getBitWidthStream() {
        return IntStream.of(
                1,
                8,
                64,
                128
        );
    }

    public static String mode(final int bitWidth) {
        return __CFB__Constants.MODE + bitWidth;
    }

    public static Stream<Arguments> getKeySizeAndBitWidthArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier) {
        return keySizeStreamSupplier.get().mapToObj(ks -> {
            return getBitWidthStream().mapToObj(bw -> {
                return Arguments.of(
                        Named.named("keySize: " + ks, ks),
                        Named.named("bitWidth: " + bw, bw)
                );
            });
        }).flatMap(Function.identity());
    }

    public static byte[] newRandomIv(final BlockCipher cipher) {
        // initialisation vector must be between one and block size length
        // https://github.com/bcgit/bc-lts-java/blob/d12b4c076c57eba0d226d422fd7ad2669758d876/core/src/main/java/org/bouncycastle/crypto/engines/AESNativeCFB.java#L58
        return _Random_TestUtils.newRandomBytes(
                ThreadLocalRandom.current().nextInt(cipher.getBlockSize()) + 1
        );
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        return getBitWidthStream()
                .mapToObj(bw -> {
                    final var engine = cipherSupplier.get();
                    try {
                        return CFBBlockCipher.newInstance(engine, bw);
                    } catch (final Exception e) {
                        log.error("failed to create cipher for bitWidth: {}", bw, e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .flatMap(c -> keySizeStreamSupplier.get().mapToObj(ks -> {
                    final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
                    final var iv = newRandomIv(c);
                    final var params = new ParametersWithIV(new KeyParameter(key), iv);
                    return Arguments.of(
                            _BlockCipher_TestUtils.named(c),
                            _ParametersWithIV_TestUtils.named(params)
                    );
                }));
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _CFB_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
