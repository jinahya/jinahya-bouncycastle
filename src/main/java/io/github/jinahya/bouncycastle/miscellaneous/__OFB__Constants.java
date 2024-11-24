package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;

/**
 * Constants for the {@value __OFB__Constants#MODE} mode.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see __OFB__Utils
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __OFB__Constants {

    /**
     * The mode of {@value}.
     */
    public static final String MODE = "OFB";

    /**
     * A list of bit-widths.
     */
    public static final List<Integer> BIT_WIDTH_LIST = List.of(
            1,
            8,
            64,
            128
    );

    // -----------------------------------------------------------------------------------------------------------------
    private __OFB__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
