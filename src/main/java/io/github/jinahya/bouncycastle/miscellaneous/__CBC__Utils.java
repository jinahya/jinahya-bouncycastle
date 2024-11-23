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

    // -----------------------------------------------------------------------------------------------------------------
    private __CBC__Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
