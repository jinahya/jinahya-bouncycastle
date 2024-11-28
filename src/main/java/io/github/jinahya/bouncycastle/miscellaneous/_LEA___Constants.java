package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Utilities for the {@value _LEA___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see _LEA___Utils
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _LEA___Constants {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    public static final String ALGORITHM = "LEA";

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * The block size of the {@value _LEA___Constants#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_BYTES
     */
    public static final int BLOCK_SIZE = 128;

    /**
     * The block size, in bytes, of the {@value _LEA___Constants#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_SIZE
     */
    public static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * An unmodifiable list of allowed key-sizes.
     */
    public static final List<Integer> ALLOWED_KEY_SIZE_LIST = List.of(
            128,
            192,
            256
    );

    /**
     * An unmodifiable list of allowed key-sizes, in bytes.
     */
    public static final List<Integer> ALLOWED_KEY_BYTES_LIST =
            ALLOWED_KEY_SIZE_LIST.stream()
                    .map(ks -> ks >> 3)
                    .collect(Collectors.toUnmodifiableList());

    // -----------------------------------------------------------------------------------------------------------------
    private _LEA___Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
