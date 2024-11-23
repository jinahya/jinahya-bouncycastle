package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.List;
import java.util.stream.Collectors;

/**
 * .
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8452">RFC 8452: AES-GCM-SIV: Nonce Misuse-Resistant
 * Authenticated Encryption</a>
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _AES_GCM_SIV___Constants {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    public static final String ALGORITHM = "AES-GCM-SIV";

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
//            192,
            256
    );

    /**
     * An unmodifiable list of allowed key sizes, in bytes.
     *
     * @deprecated Use {@link #ALLOWED_KEY_SIZE_LIST}.
     */
    @Deprecated(forRemoval = true)
    public static final List<Integer> ALLOWED_KEY_BYTES_LIST =
            _AES_GCM_SIV___Constants.ALLOWED_KEY_SIZE_LIST.stream()
                    .map(ks -> ks >> 3)
                    .collect(Collectors.toUnmodifiableList());

    // -----------------------------------------------------------------------------------------------------------------
    private _AES_GCM_SIV___Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
