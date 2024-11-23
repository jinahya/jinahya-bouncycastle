package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.stream.IntStream;

/**
 * Utilities for the {@value _DESede___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _DESede___Utils {

    /**
     * Returns a stream of allowed key-sizes for {@value _DESede___Constants#ALGORITHM} algorithm.
     *
     * @return a stream of allowed key-sizes for {@value _DESede___Constants#ALGORITHM} algorithm.
     * @see _DESede___Constants#ALLOWED_KEY_SIZE_LIST
     */
    public static IntStream getAllowedKeySizeStream() {
        return _DESede___Constants.ALLOWED_KEY_SIZE_LIST.stream().mapToInt(Integer::intValue);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _DESede___Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
