package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.stream.IntStream;

public final class __OFB__Constants {

    public static final String MODE = "OFB";

    public static IntStream getBitWidthStream() {
        return IntStream.of(
                1,
                8,
                64,
                128
        );
    }

    public static String mode(final int bitWidth) {
        return MODE + bitWidth;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private __OFB__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
