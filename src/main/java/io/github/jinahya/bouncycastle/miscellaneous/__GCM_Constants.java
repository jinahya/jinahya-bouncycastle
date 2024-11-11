package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;

final class __GCM_Constants {

    static final String MODE = "GCM";

    static final List<Integer> ALLOWED_T_LEN_LIST_GCM = List.of(
            128, 120, 112, 104, 96,
            64, 32
    );

    static final int IV_SIZE_GCM_MINIMUM = 96;

    // -----------------------------------------------------------------------------------------------------------------
    private __GCM_Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
