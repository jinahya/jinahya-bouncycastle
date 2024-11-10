package _org.bouncycastle.crypto.params;

import _org.bouncycastle.crypto._CipherParameters_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;

import java.util.Objects;

@Slf4j
public final class _ParametersWithIV_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    static String ivName(final byte[] iv) {
        return String.format("%1$d-bit iv(%2$02x, ...)", iv.length << 3, iv[0]);
    }

    public static String paramsName(final ParametersWithIV params) {
        Objects.requireNonNull(params, "params is null");
        final var iv = params.getIV();
        return _CipherParameters_TestUtils.paramsName(params.getParameters())
                + " / "
                + ivName(iv);
    }

    public static Named<ParametersWithIV> named(final ParametersWithIV params) {
        return Named.of(paramsName(params), params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _ParametersWithIV_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
