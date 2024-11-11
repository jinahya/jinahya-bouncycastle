package __symmetric;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._StreamBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.params.provider.Arguments;

import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _CTR_TestUtils {

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keyStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        return keyStreamSupplier.get().mapToObj(ks -> {
            final var cipher = SICBlockCipher.newInstance(cipherSupplier.get());
            final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
            final var iv = _Random_TestUtils.newRandomBytes(cipher.getBlockSize());
            final var params = new ParametersWithIV(new KeyParameter(key), iv);
            return Arguments.of(
                    _StreamBlockCipher_TestUtils.named((StreamBlockCipher) cipher),
                    _ParametersWithIV_TestUtils.named(params)
            );
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _CTR_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
