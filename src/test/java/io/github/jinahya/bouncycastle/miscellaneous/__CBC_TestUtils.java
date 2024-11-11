package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;

final class __CBC_TestUtils {

    static byte[] newRandomIv(final int blockBytes) {
        return _Random_TestUtils.newRandomBytes(blockBytes);
    }

    private __CBC_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}