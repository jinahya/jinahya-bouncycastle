package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.stream.IntStream;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __OFB__Utils {

    public static IntStream getBitWidthStream() {
        return IntStream.of(
                1,
                8,
                64,
                128
        );
    }

    public static String mode(final int bitWidth) {
        return __OFB__Constants.MODE + bitWidth;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private __OFB__Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
