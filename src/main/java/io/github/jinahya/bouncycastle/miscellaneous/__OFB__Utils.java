package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.stream.IntStream;

/**
 * Utilities for the {@link __OFB__Constants#MODE} mode.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see __OFB__Constants
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __OFB__Utils {

    public static IntStream getBitWidthStream() {
        return __OFB__Constants.BIT_WIDTH_LIST.stream().mapToInt(Integer::intValue);
    }

    public static int requireValidBitWidth(final int bitWidth) {
        if (!__OFB__Constants.BIT_WIDTH_LIST.contains(bitWidth)) {
            throw new IllegalArgumentException("bitWidth(" + bitWidth + ") is invalid");
        }
        return bitWidth;
    }

    /**
     * Returns a mode string for specified bit-width.
     *
     * @param bitWidth the bit-width.
     * @return a mode string for specified bit-width
     */
    public static String mode(final int bitWidth) {
        return __OFB__Constants.MODE + requireValidBitWidth(bitWidth);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private __OFB__Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
