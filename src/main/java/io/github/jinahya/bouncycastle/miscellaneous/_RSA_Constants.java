package io.github.jinahya.bouncycastle.miscellaneous;

/**
 * Constants for the {@value _RSA_Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class _RSA_Constants {

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
    private _RSA_Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
