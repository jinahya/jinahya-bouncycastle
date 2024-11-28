package io.github.jinahya.bouncycastle.miscellaneous;

import io.github.jinahya.bouncycastle.crypto.JinahyaBufferedBlockCipherCrypto;
import io.github.jinahya.bouncycastle.crypto.JinahyaCrypto;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.function.Supplier;

/**
 * Utilities for the {@value __CBC__Constants#MODE} mode.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __CBC_PKCS7Padding_Utils {

    static JinahyaCrypto newJinahyaCrypto(final byte[] key, final byte[] iv,
                                          final Supplier<? extends BlockCipher> cipherSupplier) {
        final var cipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(cipherSupplier.get()),
                new PKCS7Padding()
        );
        final var params = new ParametersWithIV(
                new KeyParameter(key),
                iv
        );
        return new JinahyaBufferedBlockCipherCrypto(cipher, params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private __CBC_PKCS7Padding_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
