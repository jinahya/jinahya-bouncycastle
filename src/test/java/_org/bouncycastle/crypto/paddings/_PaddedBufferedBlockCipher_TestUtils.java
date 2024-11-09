package _org.bouncycastle.crypto.paddings;

import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import io.github.jinahya.bouncycastle.crypto.paddings.JinahyaPaddedBufferedBlockCipherUtils;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.junit.jupiter.api.Named;

import java.util.Objects;

public final class _PaddedBufferedBlockCipher_TestUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static String cipherName(final PaddedBufferedBlockCipher cipher) {
        Objects.requireNonNull(cipher, "cipher is null");
        return _BlockCipher_TestUtils.cipherName(cipher.getUnderlyingCipher()) +
                '/' +
                _BlockCipherPadding_TestUtils.paddingName(JinahyaPaddedBufferedBlockCipherUtils.getPadding(cipher));
    }

    public static Named named(final PaddedBufferedBlockCipher cipher) {
        return Named.of(cipherName(cipher), cipher);
    }

    private _PaddedBufferedBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
