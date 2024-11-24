package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;
import java.util.stream.IntStream;

/**
 * Utilities for the {@value _Camellia___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _Camellia___Utils {

    /**
     * Returns a stream of allowed key-sizes.
     *
     * @return a stream of allowed key-sizes.
     * @see _Camellia___Constants#ALLOWED_KEY_SIZE_LIST
     */
    public static IntStream getAllowedKeySizeStream() {
        return _Camellia___Constants.ALLOWED_KEY_SIZE_LIST.stream().mapToInt(Integer::intValue);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] requireValidKey(final byte[] key) {
        Objects.requireNonNull(key, "key is null");
        if (!_Camellia___Constants.ALLOWED_KEY_BYTES_LIST.contains(key.length)) {
            throw new IllegalArgumentException("key.length(" + key.length + ") is not allowed");
        }
        return key;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static String getTransformation(final String mode, final String padding) {
        Objects.requireNonNull(mode, "mode is null");
        Objects.requireNonNull(padding, "padding is null");
        return _Camellia___Constants.ALGORITHM + '/' + mode + '/' + padding;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _Camellia___Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
