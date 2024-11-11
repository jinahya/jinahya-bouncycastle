package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;
import java.util.stream.Collectors;

final class _AES__Constants {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    static final String ALGORITHM = "AES";

    /**
     * The block size of the {@value #ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_BYTES
     */
    static final int BLOCK_SIZE = 128;

    /**
     * The block size, in bytes, of the {@value #ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_SIZE
     */
    static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    /**
     * A list of allowed key sizes.
     */
    static final List<Integer> ALLOWED_KEY_SIZE_LIST = List.of(
            128,
            192,
            256
    );

    /**
     * A list of allowed key sizes, in bytes.
     */
    public static final List<Integer> ALLOWED_KEY_BYTES_LIST =
            _AES__Constants.ALLOWED_KEY_SIZE_LIST.stream()
                    .map(ks -> ks >> 3)
                    .collect(Collectors.toUnmodifiableList());

    // -----------------------------------------------------------------------------------------------------------------
    private _AES__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
