package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;
import java.util.stream.IntStream;

/**
 * Utilities for the {@value _LEA___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _LEA___Utils {

    public static IntStream getAllowedKeySizeStream() {
        return _LEA___Constants.ALLOWED_KEY_SIZES_LIST.stream().mapToInt(Integer::intValue);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static byte[] requireValidKey(final byte[] key) {
        if (!_ARIA___Constants.ALLOWED_KEY_BYTES_LIST.contains(Objects.requireNonNull(key, "key is null").length)) {
            throw new IllegalArgumentException("key.length(" + key.length + ") is not allowed");
        }
        return key;
    }

    static byte[] requireValidIv(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length != _ARIA___Constants.BLOCK_BYTES) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + _ARIA___Constants.BLOCK_BYTES);
        }
        return iv;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _LEA___Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
