package io.github.jinahya.bouncycastle.miscellaneous;

/**
 * Constants for the {@value _RSA___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _RSA___Constants {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    public static final String ALGORITHM = "RSA";

    // -----------------------------------------------------------------------------------------------------------------
    public static final int HASH_SIZE_SHA1 = 160;

    public static final int H_LEN_SHA1 = HASH_SIZE_SHA1 >> 3;

    public static final int HASH_SIZE_SHA256 = 256;

    public static final int H_LEN_SHA256 = HASH_SIZE_SHA256 >> 3;

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA___Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
