package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.params.provider.Arguments;

import java.util.stream.Stream;

public final class _SEED___TestUtils {

    public static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return _SEED___Constants.ALLOWED_KEY_SIZE_LIST.stream().map(ks -> {
            return Arguments.of(
                    _BlockCipher_TestUtils.named(new SEEDEngine()),
                    _KeyParameters_TestUtils.named(
                            new KeyParameter(_Random_TestUtils.newRandomBytes(ks >> 3))
                    )
            );
        });
    }

    private _SEED___TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}