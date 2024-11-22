package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.Objects;
import java.util.stream.IntStream;

public final class _SEED___Utils {

    public static IntStream getAllowedKeySizeStream() {
        return _SEED___Constants.ALLOWED_KEY_SIZE_LIST.stream().mapToInt(Integer::intValue);
    }

    static byte[] requireValidKey(final byte[] key) {
        if (!_SEED___Constants.ALLOWED_KEY_BYTES_LIST.contains(Objects.requireNonNull(key, "key is null").length)) {
            throw new IllegalArgumentException("key.length(" + key.length + ") is not allowed");
        }
        return key;
    }

    static byte[] requireValidIv(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length != _SEED___Constants.BLOCK_BYTES) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + _SEED___Constants.BLOCK_BYTES);
        }
        return iv;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _SEED___Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
