package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;
import java.util.stream.IntStream;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _SEED___Utils {

    public static IntStream getAllowedKeySizeStream() {
        return _SEED___Constants.ALLOWED_KEY_SIZE_LIST.stream().mapToInt(Integer::intValue);
    }

    static byte[] requireValidKey(final byte[] key) {
        Objects.requireNonNull(key, "key is null");
        if (!_SEED___Constants.ALLOWED_KEY_BYTES_LIST.contains(key.length)) {
            throw new IllegalArgumentException("key.length(" + key.length + ") is not allowed");
        }
        return key;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _SEED___Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
