package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.modes._AEADBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._AEADParameters_TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.GCMSIVBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.params.provider.Arguments;

import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class _AES_GCM_SIV__TestUtils {

    public static int newRandomMacSize() {
        // https://github.com/bcgit/bc-lts-java/blob/d12b4c076c57eba0d226d422fd7ad2669758d876/core/src/main/java/org/bouncycastle/crypto/modes/GCMBlockCipher.java#L141
//        return ThreadLocalRandom.current().nextInt(12, 17) << 3; // [96...128]
        return ThreadLocalRandom.current().nextInt(
                __GCM__Constants.MAC_SIZE_MINIMUM,
                __GCM__Constants.MAC_SIZE_MAXIMUM + 1
        ) >> 3 << 3;
    }

    public static byte[] newRandomNonce() {
        // IV must be at least 12 byte
        // https://github.com/bcgit/bc-lts-java/blob/d12b4c076c57eba0d226d422fd7ad2669758d876/core/src/main/java/org/bouncycastle/crypto/modes/GCMBlockCipher.java#L166
//        return _Random_TestUtils.newRandomBytes(
//                ThreadLocalRandom.current().nextInt(128) + (__GCM__Constants.IV_SIZE_MINIMUM >> 3)
//        );
        return _Random_TestUtils.newRandomBytes(12);
    }

    public static Stream<Arguments> getCipherAndParamsArgumentsStream(
            final Supplier<? extends IntStream> keySizeStreamSupplier,
            final Supplier<? extends BlockCipher> cipherSupplier) {
        Objects.requireNonNull(keySizeStreamSupplier, "keySizeStreamSupplier is null");
        Objects.requireNonNull(cipherSupplier, "cipherSupplier is null");
        return keySizeStreamSupplier.get().mapToObj(ks -> {
            final var cipher = new GCMSIVBlockCipher(cipherSupplier.get());
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

    static int randomTLen() {
        return __GCM__Constants.ALLOWED_T_LEN_LIST.get(
                ThreadLocalRandom.current().nextInt(__GCM__Constants.ALLOWED_T_LEN_LIST.size())
        );
    }

    static int randomIvBytes() {
        return ThreadLocalRandom.current().nextInt(128) + __GCM__Constants.IV_SIZE_MINIMUM;
    }

    static byte[] randomIv() {
        return _Random_TestUtils.newRandomBytes(randomIvBytes());
    }

    static byte[] randomAad() {
        return ThreadLocalRandom.current().nextBoolean()
                ? null
                : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
    }

    private _AES_GCM_SIV__TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}