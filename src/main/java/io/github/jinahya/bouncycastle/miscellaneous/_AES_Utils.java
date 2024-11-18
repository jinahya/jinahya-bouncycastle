package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;

/**
 * Utilities for the {@value _AES_Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
final class _AES_Utils {

    // -----------------------------------------------------------------------------------------------------------------
    static byte[] requireValidKey(final byte[] key) {
        if (!_AES_Constants.ALLOWED_KEY_BYTES_LIST.contains(Objects.requireNonNull(key, "key is null").length)) {
            throw new IllegalArgumentException("key.length(" + key.length + ") is not allowed");
        }
        return key;
    }

    static byte[] requireValidIv(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length != _AES_Constants.BLOCK_BYTES) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + _AES_Constants.BLOCK_BYTES);
        }
        return iv;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static String getTransformation(final String mode, final String padding) {
        Objects.requireNonNull(mode, "mode is null");
        Objects.requireNonNull(padding, "padding is null");
        return _AES_Constants.ALGORITHM + '/' + mode + '/' + padding;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _AES_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
