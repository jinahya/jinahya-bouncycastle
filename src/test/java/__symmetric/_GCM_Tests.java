package __symmetric;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.modes._AEADBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._AEADParameters_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
public final class _GCM_Tests {

    public static int newRandomMacSize() {
        // https://github.com/bcgit/bc-lts-java/blob/d12b4c076c57eba0d226d422fd7ad2669758d876/core/src/main/java/org/bouncycastle/crypto/modes/GCMBlockCipher.java#L141
        return ThreadLocalRandom.current().nextInt(12, 17) << 3; // [96...128]
    }

    public static byte[] newRandomNonce() {
        // IV must be at least 12 byte
        // https://github.com/bcgit/bc-lts-java/blob/d12b4c076c57eba0d226d422fd7ad2669758d876/core/src/main/java/org/bouncycastle/crypto/modes/GCMBlockCipher.java#L166
        return _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(128) + 12);
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return keySizeStreamSupplier.get().mapToObj(ks -> {
            final var cipher = GCMBlockCipher.newInstance(cipherSupplier.get());
            final var key = _Random_TestUtils.newRandomBytes(ks >> 3);
            final var macSize = newRandomMacSize();
            final var nonce = newRandomNonce();
            final var associatedText = ThreadLocalRandom.current().nextBoolean()
                    ? null
                    : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
            final var params = new AEADParameters(
                    new KeyParameter(key),
                    macSize,
                    nonce,
                    associatedText
            );
            return Arguments.of(
                    _AEADBlockCipher_TestUtils.named(cipher),
                    _AEADParameters_TestUtils.named(params)
            );
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static final String MODE = "GCM";

    public static IntStream getTLenStream() {
        return IntStream.of(
                128, 120, 112, 104, 96,
                64, 32 // for certain applications
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _GCM_Tests() {
        throw new AssertionError("instantiation is not allowed");
    }
}
