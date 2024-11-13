package __asymmetric;

import java.util.stream.IntStream;

public final class _RSA__Constants {

    public static final String ALGORITHM = "RSA";

    public static IntStream getKeySizeStream() {
        return IntStream.of(
                1024,
                2048,
                3072
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static final int HASH_SIZE_SHA1 = 160;

    public static final int H_LEN_SHA1 = HASH_SIZE_SHA1 >> 3;

    public static final int HASH_SIZE_SHA256 = 256;

    public static final int H_LEN_SHA256 = HASH_SIZE_SHA256 >> 3;

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
