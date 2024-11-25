package _org.bouncycastle.crypto.params;

import _javax.security._Random_TestUtils;
import io.github.jinahya.bouncycastle.crypto.params.JinahyaKeyParametersUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.Named;

import java.util.Objects;

@Slf4j
public final class _KeyParameters_TestUtils {

    public static CipherParameters getKeyParameters(final CipherParameters params) {
        Objects.requireNonNull(params, "params is null");
        if (params instanceof KeyParameter) {
            return params;
        }
        if (params instanceof ParametersWithIV p) {
            return getKeyParameters(p.getParameters());
        }
        if (params instanceof AEADParameters p) {
            return p.getKey();
        }
        throw new IllegalArgumentException("unable to get the key parameter from " + params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static String keyString(final byte[] key) {
        return String.format("%1$d-bit key(%2$02x, ...)", key.length << 3, key[0]);
    }

    public static String paramsString(final KeyParameter params) {
        Objects.requireNonNull(params, "params is null");
        final var key = JinahyaKeyParametersUtils.getKey(params);
        return keyString(key);
    }

    public static <T extends KeyParameter> Named<T> named(final T params) {
        return Named.of(paramsString(params), params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static KeyParameter newRandomInstance(final int keysize) {
        return new KeyParameter(_Random_TestUtils.newRandomBytes(keysize >> 3));
    }

    public static KeyParameter newRandomInstance(final BlockCipher cipher) {
        return newRandomInstance(cipher.getBlockSize() << 3);

    }

    // -----------------------------------------------------------------------------------------------------------------
    private _KeyParameters_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
