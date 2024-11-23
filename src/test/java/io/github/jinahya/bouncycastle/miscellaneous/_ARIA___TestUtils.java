package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.params.provider.Arguments;

import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

public final class _ARIA___TestUtils {

    public static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return _ARIA___Constants.ALLOWED_KEY_BYTES_LIST.stream().map(kb -> {
            return Arguments.of(
                    _BlockCipher_TestUtils.named(new ARIAEngine()),
                    _KeyParameters_TestUtils.named(
                            new KeyParameter(_Random_TestUtils.newRandomBytes(kb))
                    )
            );
        });
    }

    static int randomKeyBytes() {
        return _ARIA___Constants.ALLOWED_KEY_BYTES_LIST.get(
                ThreadLocalRandom.current().nextInt(_ARIA___Constants.ALLOWED_KEY_BYTES_LIST.size())
        );
    }

    static byte[] randomKey() {
        return _Random_TestUtils.newRandomBytes(randomKeyBytes());
    }

    private _ARIA___TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}