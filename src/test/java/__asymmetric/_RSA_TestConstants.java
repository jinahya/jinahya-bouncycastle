package __asymmetric;

import java.util.stream.IntStream;

public final class _RSA_TestConstants {

    public static IntStream getKeySizeStream() {
        return IntStream.of(
                1024,
                2048,
                3072
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA_TestConstants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
