package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;
import java.util.stream.Collectors;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _Camellia___Constants {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    public static final String ALGORITHM = "Camellia";

    /**
     * The block size of the {@value #ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_BYTES
     */
    public static final int BLOCK_SIZE = 128;

    /**
     * The block size, in bytes, of the {@value #ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_SIZE
     */
    public static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    /**
     * An unmodifiable list of allowed key sizes.
     */
    public static final List<Integer> ALLOWED_KEY_SIZE_LIST = List.of(
            128,
            192,
            256
    );

    /**
     * An unmodifiable list of allowed key sizes, in bytes.
     */
    static final List<Integer> ALLOWED_KEY_BYTES_LIST =
            _Camellia___Constants.ALLOWED_KEY_SIZE_LIST.stream()
                    .map(ks -> ks >> 3)
                    .collect(Collectors.toUnmodifiableList());

    // -----------------------------------------------------------------------------------------------------------------
    private _Camellia___Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
