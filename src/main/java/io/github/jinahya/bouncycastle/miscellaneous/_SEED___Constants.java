package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;
import java.util.stream.Collectors;

public final class _SEED___Constants {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    public static final String ALGORITHM = "SEED";

    /**
     * The block size of the {@value _SEED___Constants#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_BYTES
     */
    public static final int BLOCK_SIZE = 128;

    /**
     * The block size, in bytes, of the {@value _SEED___Constants#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_SIZE
     */
    public static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    /**
     * An unmodifiable list of allowed key sizes.
     */
    public static final List<Integer> ALLOWED_KEY_SIZE_LIST = List.of(
            128
    );

    /**
     * An unmodifiable list of allowed key sizes, in bytes.
     *
     * @deprecated Use {@link #ALLOWED_KEY_SIZE_LIST}
     */
    @Deprecated(forRemoval = true)
    public static final List<Integer> ALLOWED_KEY_BYTES_LIST =
            _SEED___Constants.ALLOWED_KEY_SIZE_LIST.stream()
                    .map(ks -> ks >> 3)
                    .collect(Collectors.toUnmodifiableList());

    // -----------------------------------------------------------------------------------------------------------------
    private _SEED___Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
