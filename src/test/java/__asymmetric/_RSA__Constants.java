package __asymmetric;

import java.util.stream.IntStream;

public final class _RSA__Constants {

    public static final String ALGORITHM = "RSA";

    public static IntStream getKeySizeStream() {
        return IntStream.of(
                1024,
                2048
        );
    }

    private _RSA__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
