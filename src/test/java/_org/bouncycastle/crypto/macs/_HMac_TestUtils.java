package _org.bouncycastle.crypto.macs;

import _org.bouncycastle.crypto._Digest_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.macs.HMac;

@Slf4j
public final class _HMac_TestUtils {

    public static HMac newRandomInstance() {
        final var instance = new HMac(_Digest_TestUtils.newRandomDigest());
        instance.init(_KeyParameters_TestUtils.newRandomInstance(128));
        return instance;
    }

    private _HMac_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
