package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;
import java.util.stream.IntStream;

/**
 * Utilities for the {@value _AES___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see _AES___Constants
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _AES___Utils {

    /**
     * Returns a stream of allowed key-sizes.
     *
     * @return a stream of allowed key-sizes.
     * @see _AES___Constants#ALLOWED_KEY_SIZE_LIST
     * @see #getAllowedKeyBytesStream()
     */
    public static IntStream getAllowedKeySizeStream() {
        return _AES___Constants.ALLOWED_KEY_SIZE_LIST.stream().mapToInt(Integer::intValue);
    }

    /**
     * Returns a stream of allowed key-sizes, in bytes.
     *
     * @return a stream of allowed key-sizes.
     * @see _AES___Constants#ALLOWED_KEY_BYTES_LIST
     * @see #getAllowedKeySizeStream()
     */
    public static IntStream getAllowedKeyBytesStream() {
        return _AES___Constants.ALLOWED_KEY_BYTES_LIST.stream().mapToInt(Integer::intValue);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static byte[] requireValidKey(final byte[] key) {
        Objects.requireNonNull(key, "key is null");
        if (!_AES___Constants.ALLOWED_KEY_BYTES_LIST.contains(key.length)) {
            throw new IllegalArgumentException("key.length(" + key.length + ") is not allowed");
        }
        return key;
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Returns a transformation string with specified mode and padding.
     *
     * @param mode    the mode.
     * @param padding the padding.
     * @return a string of {@code AES}/{@code mode}/{@code padding}.
     */
    public static String getTransformation(final String mode, final String padding) {
        Objects.requireNonNull(mode, "mode is null");
        Objects.requireNonNull(padding, "padding is null");
        return _AES___Constants.ALGORITHM + '/' + mode + '/' + padding;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _AES___Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
