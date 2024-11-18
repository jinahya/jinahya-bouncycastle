package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;

import java.util.concurrent.ThreadLocalRandom;

final class _AES__TestUtils {

    static int randomKeyBytes() {
        return _AES___Constants.ALLOWED_KEY_BYTES_LIST.get(
                ThreadLocalRandom.current().nextInt(_AES___Constants.ALLOWED_KEY_BYTES_LIST.size())
        );
    }

    static byte[] randomKey() {
        return _Random_TestUtils.newRandomBytes(randomKeyBytes());
    }

    private _AES__TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}