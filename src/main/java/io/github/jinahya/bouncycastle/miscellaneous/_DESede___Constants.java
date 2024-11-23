package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;

public final class _DESede___Constants {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    public static final String ALGORITHM = "DESede";

    /**
     * The block size of the {@value #ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_BYTES
     */
    public static final int BLOCK_SIZE = 64;

    /**
     * The block size, in bytes, of the {@value #ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_SIZE
     */
    public static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    /**
     * An unmodifiable list of allowed key-sizes.
     */
    public static final List<Integer> ALLOWED_KEY_SIZE_LIST = List.of(
            128,
            192
    );

    // -----------------------------------------------------------------------------------------------------------------
    private _DESede___Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
