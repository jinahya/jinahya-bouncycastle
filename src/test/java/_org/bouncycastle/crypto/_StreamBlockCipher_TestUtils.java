package _org.bouncycastle.crypto;

import org.bouncycastle.crypto.StreamBlockCipher;
import org.junit.jupiter.api.Named;

import java.util.Objects;

public final class _StreamBlockCipher_TestUtils {

    public static String cipherName(final StreamBlockCipher cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        return _StreamCipher_TestUtils.cipherName(cipher)
                + '/' + _BlockCipher_TestUtils.name(cipher.getUnderlyingCipher());
    }

    public static <T extends StreamBlockCipher> Named<T> named(final T cipher) {
        return Named.of(cipherName(cipher), cipher);
    }

    private _StreamBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
