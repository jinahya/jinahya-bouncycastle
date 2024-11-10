package _org.bouncycastle.crypto.params;

import io.github.jinahya.bouncycastle.crypto.params.JinahyaKeyParametersUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Named;

import java.util.Objects;

@Slf4j
public final class _KeyParameters_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static String keyName(final byte[] key) {
        return String.format("%1$d-bit key(%2$02x, ...)", key.length << 3, key[0]);
    }

    public static String paramsName(final KeyParameter params) {
        Objects.requireNonNull(params, "params is null");
        final var key = JinahyaKeyParametersUtils.getKey(params);
        return keyName(key);
    }

    public static <T extends KeyParameter> Named<T> named(final T params) {
        return Named.of(paramsName(params), params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _KeyParameters_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
