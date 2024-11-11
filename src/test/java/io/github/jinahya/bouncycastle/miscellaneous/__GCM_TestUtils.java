package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;

import java.util.concurrent.ThreadLocalRandom;

final class __GCM_TestUtils {

    static int randomTLen() {
        return __GCM_Constants.ALLOWED_T_LEN_LIST_GCM.get(
                ThreadLocalRandom.current().nextInt(__GCM_Constants.ALLOWED_T_LEN_LIST_GCM.size())
        );
    }

    static int randomIvBytes() {
        return ThreadLocalRandom.current().nextInt(128) + __GCM_Constants.IV_SIZE_GCM_MINIMUM;
    }

    static byte[] randomIv() {
        return _Random_TestUtils.newRandomBytes(randomIvBytes());
    }

    static byte[] randomAad() {
        return ThreadLocalRandom.current().nextBoolean()
                ? null
                : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
    }

    private __GCM_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}