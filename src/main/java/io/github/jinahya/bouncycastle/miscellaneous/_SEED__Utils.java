package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;

final class _SEED__Utils {

    static byte[] requireValidKey(final byte[] key) {
        if (!_SEED__Constants.ALLOWED_KEY_BYTES_LIST.contains(Objects.requireNonNull(key, "key is null").length)) {
            throw new IllegalArgumentException("key.length(" + key.length + ") is not allowed");
        }
        return key;
    }

    static byte[] requireValidIv(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length != _SEED__Constants.BLOCK_BYTES) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + _SEED__Constants.BLOCK_BYTES);
        }
        return iv;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _SEED__Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
