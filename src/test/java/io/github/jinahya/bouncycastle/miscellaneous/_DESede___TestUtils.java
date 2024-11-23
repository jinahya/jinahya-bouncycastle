package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.params.provider.Arguments;

import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

public final class _DESede___TestUtils {

    public static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return _DESede___Utils.getAllowedKeySizeStream().mapToObj(ks -> {
            return Arguments.of(
                    _BlockCipher_TestUtils.named(new DESedeEngine()),
                    _KeyParameters_TestUtils.named(
                            new KeyParameter(_Random_TestUtils.newRandomBytes(ks >> 3))
                    )
            );
        });
    }

    static int randomKeySize() {
        return _AES___Constants.ALLOWED_KEY_SIZE_LIST.get(
                ThreadLocalRandom.current().nextInt(_AES___Constants.ALLOWED_KEY_SIZE_LIST.size())
        );
    }

    static byte[] randomKey() {
        return _Random_TestUtils.newRandomBytes(randomKeySize() >> 3);
    }

    private _DESede___TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}