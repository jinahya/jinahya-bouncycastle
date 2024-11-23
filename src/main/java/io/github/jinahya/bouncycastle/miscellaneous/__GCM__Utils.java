package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
final class __GCM__Utils {

    static int requireValid_tLen_GCM(final int tLen) {
        __GCM__Constants.ALLOWED_T_LEN_LIST.contains(tLen);
        return tLen;
    }

    static byte[] requireValid_iv_GCM(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length < __GCM__Constants.IV_SIZE_MINIMUM) {
            throw new IllegalArgumentException(
                    "iv.length(" + iv.length + ") < " + __GCM__Constants.IV_SIZE_MINIMUM);
        }
        return iv;
    }

    private __GCM__Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
