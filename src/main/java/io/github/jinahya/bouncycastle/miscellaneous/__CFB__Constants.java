package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __CFB__Constants {

    public static final String MODE = "CFB";

    public static final List<Integer> BIT_WIDTH_LIST = List.of(
            1,
            8,
            64,
            128
    );

    // -----------------------------------------------------------------------------------------------------------------
    private __CFB__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
