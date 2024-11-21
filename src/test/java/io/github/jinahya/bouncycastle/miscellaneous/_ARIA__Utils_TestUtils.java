package io.github.jinahya.bouncycastle.miscellaneous;

import java.util.concurrent.ThreadLocalRandom;

final class _ARIA__Utils_TestUtils {

    static int randomKeyBytes() {
        return _ARIA___Constants.ALLOWED_KEY_BYTES_LIST.get(
                ThreadLocalRandom.current().nextInt(_ARIA___Constants.ALLOWED_KEY_BYTES_LIST.size())
        );
    }

    private _ARIA__Utils_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}