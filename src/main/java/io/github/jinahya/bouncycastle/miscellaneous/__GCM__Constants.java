package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;

public final class __GCM__Constants {

    /**
     * The mode of {@value}.
     */
    public static final String MODE = "GCM";

    /**
     * An unmodifiable list of allowed tag lengths.
     */
    static final List<Integer> ALLOWED_T_LEN_LIST_GCM = List.of(
            128, 120, 112, 104, 96,
            64, 32
    );

    static final int IV_SIZE_GCM_MINIMUM = 96;

    // -----------------------------------------------------------------------------------------------------------------
    private __GCM__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
