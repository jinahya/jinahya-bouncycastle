package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Utilities for the {@value _ARIA__Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class _ARIA__Constants {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    public static final String ALGORITHM = "ARIA";

    /**
     * The block size of the {@value _ARIA__Constants#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_BYTES
     */
    public static final int BLOCK_SIZE = 128;

    /**
     * The block size, in bytes, of the {@value _ARIA__Constants#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_SIZE
     */
    public static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    /**
     * A list of allowed key sizes.
     */
    public static final List<Integer> ALLOWED_KEY_SIZES = List.of(
            128,
            192,
            256
    );

    /**
     * A list of allowed key sizes, in bytes.
     */
    public static final List<Integer> ALLOWED_KEY_BYTES =
            ALLOWED_KEY_SIZES.stream()
                    .map(ks -> ks >> 3)
                    .collect(Collectors.toUnmodifiableList());

    // -----------------------------------------------------------------------------------------------------------------
    private _ARIA__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
