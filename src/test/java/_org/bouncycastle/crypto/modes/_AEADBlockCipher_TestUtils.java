package _org.bouncycastle.crypto.modes;

import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.junit.jupiter.api.Named;

public final class _AEADBlockCipher_TestUtils {

    public static String name(final AEADBlockCipher cipher) {
        return cipher.getAlgorithmName() +
                '/' +
                _BlockCipher_TestUtils.name(cipher.getUnderlyingCipher());
    }

    public static <T extends AEADBlockCipher> Named<T> named(final T cipher) {
        return Named.of(name(cipher), cipher);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _AEADBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
