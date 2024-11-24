package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;

/**
 * Utilities for the {@value __CBC__Constants#MODE} mode.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __CBC__Utils {

    public static byte[] requireValidIv(final byte[] iv, final int blockBytes) {
        if (Objects.requireNonNull(iv, "iv is null").length != blockBytes) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != blockBytes(" + blockBytes + ")");
        }
        return iv;
    }

    public static String getTransformation(final String algorithm, final String padding) {
        Objects.requireNonNull(algorithm, "algorithm is null");
        Objects.requireNonNull(padding, "padding is null");
        return algorithm + '/' + __CBC__Constants.MODE + '/' + padding;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private __CBC__Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
