package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.stream.IntStream;

public final class _RSA___TestConstants {

    public static IntStream getKeySizeStream() {
        return IntStream.of(
                1024,
                2048,
                3072
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA___TestConstants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
