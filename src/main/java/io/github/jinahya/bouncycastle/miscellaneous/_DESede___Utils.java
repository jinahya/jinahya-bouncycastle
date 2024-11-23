package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.stream.IntStream;

/**
 * Utilities for the {@value _DESede___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class _DESede___Utils {

    public static IntStream getAllowedKeySizeStream() {
        return _DESede___Constants.ALLOWED_KEY_SIZE_LIST.stream().mapToInt(Integer::intValue);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _DESede___Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
