package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.stream.IntStream;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __CFB__Utils {

    public static IntStream getBitWidthStream() {
        return __CFB__Constants.BIT_WIDTH_LIST.stream()
                .mapToInt(Integer::intValue);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private __CFB__Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
