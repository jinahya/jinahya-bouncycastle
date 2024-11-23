package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __GCM__Constants {

    /**
     * The mode of {@value}.
     */
    public static final String MODE = "GCM";

    /**
     * An unmodifiable list of allowed tag-lengths.
     */
    static final List<Integer> ALLOWED_T_LEN_LIST = List.of(
            128, 120, 112, 104, 96,
            64, 32 // for certain applications
    );

    public static final int IV_SIZE_MINIMUM = 12 << 3;

    public static final int MAC_SIZE_MINIMUM = 12 << 3;

    public static final int MAC_SIZE_MAXIMUM = 16 << 3;

    // -----------------------------------------------------------------------------------------------------------------
    private __GCM__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
