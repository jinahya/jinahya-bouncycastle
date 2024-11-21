package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;

/**
 * Utilities for the {@value _AES___Constants#ALGORITHM} algorithm and {@link __GCM__Constants#MODE} mode.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class _AES_GCM__Utils {

    static byte[] requireValidIv(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length != _AES___Constants.BLOCK_BYTES) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + _AES___Constants.BLOCK_BYTES);
        }
        return iv;
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static String getTransformation(final String padding) {
        return _AES___Utils.getTransformation(__GCM__Constants.MODE, padding);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _AES_GCM__Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
