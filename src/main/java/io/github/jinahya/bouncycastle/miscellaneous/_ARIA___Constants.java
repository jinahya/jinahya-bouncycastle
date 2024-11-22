package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Utilities for the {@value _ARIA___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class _ARIA___Constants {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    static final String ALGORITHM = "ARIA";

    /**
     * The block size of the {@value _ARIA___Constants#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_BYTES
     */
    static final int BLOCK_SIZE = 128;

    /**
     * The block size, in bytes, of the {@value _ARIA___Constants#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_SIZE
     */
    static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    /**
     * A list of allowed key sizes.
     */
    public static final List<Integer> ALLOWED_KEY_SIZES_LIST = List.of(
            128,
            192,
            256
    );

    /**
     * A list of allowed key sizes, in bytes.
     */
    static final List<Integer> ALLOWED_KEY_BYTES_LIST =
            ALLOWED_KEY_SIZES_LIST.stream()
                    .map(ks -> ks >> 3)
                    .collect(Collectors.toUnmodifiableList());

    // -----------------------------------------------------------------------------------------------------------------
    private _ARIA___Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
