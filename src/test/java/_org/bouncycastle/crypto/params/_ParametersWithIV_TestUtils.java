package _org.bouncycastle.crypto.params;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._CipherParameters_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;

import java.util.Objects;

@Slf4j
public final class _ParametersWithIV_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    static String ivString(final byte[] iv) {
        return String.format("%1$d-bit iv(%2$02x, ...)", iv.length << 3, iv[0]);
    }

    public static String paramsString(final ParametersWithIV params) {
        Objects.requireNonNull(params, "params is null");
        final var iv = params.getIV();
        return _CipherParameters_TestUtils.name(params.getParameters())
                + " / "
                + ivString(iv);
    }

    public static Named<ParametersWithIV> named(final ParametersWithIV params) {
        return Named.of(paramsString(params), params);
    }

    public static ParametersWithIV newRandomInstance(final CipherParameters params, final int ivbytes) {
        return new ParametersWithIV(params, _Random_TestUtils.newRandomBytes(ivbytes));
    }

    public static ParametersWithIV newRandomInstance(final BlockCipher cipher, final int ivbytes) {
        return newRandomInstance(_KeyParameters_TestUtils.newRandomInstance(cipher), ivbytes);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _ParametersWithIV_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
