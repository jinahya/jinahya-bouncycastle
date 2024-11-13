package io.github.jinahya.bouncycastle.miscellaneous;

import io.github.jinahya.bouncycastle.crypto.JinahyaCrypto;
import io.github.jinahya.bouncycastle.crypto.modes.JinahyaAEADCipherCrypto;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * Utilities for the {@value _AES__Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaRSAUtils {

    // ----------------------------------------------------------------------------------------------- /ECB/PKCS1Padding
    private static byte[] _ECB_PKCS1Padding(final boolean forEncryption, final AsymmetricKeyParameter key,
                                                   final CipherParameters params, final byte[] in)
            throws InvalidCipherTextException {
        Objects.requireNonNull(key, "key is null");
        Objects.requireNonNull(params, "params is null");
        Objects.requireNonNull(in, "in is null");
        final var cipher = new PKCS1Encoding(new RSAEngine());
        cipher.init(forEncryption, params);
        return cipher.processBlock(in, 0, in.length);
    }

//    public static byte[] encrypt_CBC_PKCS7Padding(final byte[] key, final byte[] iv, final byte[] in) {
//        return _ECB_PKCS1Padding(key, iv)
//                .encrypt(in);
//    }
//
//    public static byte[] decrypt_CBC_PKCS7Padding(final byte[] key, final byte[] iv, final byte[] in) {
//        return _ECB_PKCS1Padding(key, iv)
//                .decrypt(in);
//    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaRSAUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
