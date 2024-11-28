package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;
import java.util.stream.IntStream;

/**
 * Utilities for the {@value _LEA___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see _LEA___Constants
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _LEA___Utils {

    public static IntStream getAllowedKeySizeStream() {
        return _LEA___Constants.ALLOWED_KEY_SIZE_LIST.stream().mapToInt(Integer::intValue);
    }

    public static IntStream getAllowedKeyBytesStream() {
        return _LEA___Constants.ALLOWED_KEY_BYTES_LIST.stream().mapToInt(Integer::intValue);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static byte[] requireValidKey(final byte[] key) {
        Objects.requireNonNull(key, "key is null");
        if (!_LEA___Constants.ALLOWED_KEY_BYTES_LIST.contains(key.length)) {
            throw new IllegalArgumentException("key.length(" + key.length + ") is not allowed");
        }
        return key;
    }

    static byte[] requireValidIv(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length != _LEA___Constants.BLOCK_BYTES) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + _LEA___Constants.BLOCK_BYTES);
        }
        return iv;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _LEA___Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
