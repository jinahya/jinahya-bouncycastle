package _org.bouncycastle.crypto.macs;

import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import io.github.jinahya.bouncycastle.miscellaneous.__GCM__TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;

@Slf4j
public final class _GMac_TestUtils {

    public static GMac newRandomInstance() {
        final int macSizeBits = __GCM__TestUtils.newRandomMacSize();
        final var cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        final var instance = new GMac(cipher, macSizeBits);
        final var params = _ParametersWithIV_TestUtils.newRandomInstance(
                cipher.getUnderlyingCipher(),
                __GCM__TestUtils.newRandomMacSize() >> 3
        );
        instance.init(params);
        return instance;
    }

    private _GMac_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
