package __symmetric;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.paddings._BlockCipherPadding_TestUtils;
import _org.bouncycastle.crypto.paddings._PaddedBufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _ECB_Tests {

    public static final String MODE = "ECB";

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends BlockCipher> cipherSupplier,
            final Supplier<? extends IntStream> keySizeStreamSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return _BlockCipherPadding_TestUtils.getBlockCipherPaddingStream()
                .flatMap(p -> keySizeStreamSupplier.get().mapToObj(ks -> {
                    final var cipher = new PaddedBufferedBlockCipher(
                            cipherSupplier.get(),
                            p
                    );
                    final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
                    final var params = new KeyParameter(key);
                    return Arguments.of(
                            _PaddedBufferedBlockCipher_TestUtils.named(cipher),
                            _KeyParameters_TestUtils.named(params)
                    );
                }));
    }

    private _ECB_Tests() {
        throw new AssertionError("instantiation is not allowed");
    }
}
