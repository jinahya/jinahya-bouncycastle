package __symmetric;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.paddings._BlockCipherPadding_TestUtils;
import _org.bouncycastle.crypto.paddings._PaddedBufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static _org.bouncycastle.crypto.paddings._BlockCipherPadding_TestUtils.getBlockCipherPaddingStream;

@Slf4j
public final class _ECB_TestUtils {

    public static Stream<Arguments> getPaddingAndKeySizeArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier) {
        return _BlockCipherPadding_TestUtils.getBlockCipherPaddingStream()
                .flatMap(p -> keySizeStreamSupplier.get().mapToObj(ks -> {
                    return Arguments.of(
                            Named.of(p.getPaddingName(), p),
                            ks
                    );
                }));
    }

    public static Stream<Arguments> getArgumentsStream(final Supplier<? extends IntStream> keySizeStreamSupplier,
                                                       final Supplier<? extends BlockCipher> cipherSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return getBlockCipherPaddingStream()
                .flatMap(p -> keySizeStreamSupplier.get().mapToObj(ks -> {
                    final var cipher = new PaddedBufferedBlockCipher(cipherSupplier.get(), p);
                    final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
                    final var params = new KeyParameter(key);
                    return Arguments.of(
                            _PaddedBufferedBlockCipher_TestUtils.named(cipher),
                            _KeyParameters_TestUtils.named(params)
                    );
                }));
    }

    public static final String MODE = "ECB";

    private _ECB_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
