package __asymmetric;

import java.util.stream.IntStream;

public final class _RSA_Tests {

    public static IntStream getKeySizeStream() {
        return IntStream.of(
                1024,
                2048
        );
    }

    private _RSA_Tests() {
        throw new AssertionError("instantiation is not allowed");
    }
}
