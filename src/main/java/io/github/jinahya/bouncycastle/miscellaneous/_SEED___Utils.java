package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;
import java.util.stream.IntStream;

/**
 * Utiltiies for the {@link _SEED___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see _SEED___Constants
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _SEED___Utils {

    // ------------------------------------------------------------------------------------------------------------- key
    private static final int[] KEY_SIZE_ARRAY =
            _SEED___Constants.ALLOWED_KEY_SIZE_LIST.stream().mapToInt(Integer::intValue).toArray();

    /**
     * Returns a stream of allowed key sizes.
     *
     * @return a stream of allowed key sizes.
     * @see #getAllowedKeyBytesStream()
     */
    public static IntStream getAllowedKeySizeStream() {
        return IntStream.of(KEY_SIZE_ARRAY);
    }

    private static final int[] KEY_BYTES_ARRAY =
            _SEED___Constants.ALLOWED_KEY_BYTES_LIST.stream().mapToInt(Integer::intValue).toArray();

    /**
     * Returns a stream of allowed key sizes, in bytes.
     *
     * @return a stream of allowed key sizes, in bytes.
     * @see #getAllowedKeySizeStream()
     */
    public static IntStream getAllowedKeyBytesStream() {
        return IntStream.of(KEY_BYTES_ARRAY);
    }

    public static byte[] requireValidKey(final byte[] key) {
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
