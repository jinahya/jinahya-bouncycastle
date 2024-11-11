package io.github.jinahya.bouncycastle.miscellaneous;

import io.github.jinahya.bouncycastle.crypto.JinahyaBufferedBlockCipherCrypto;
import io.github.jinahya.bouncycastle.crypto.JinahyaBufferedBlockCipherUtils;
import io.github.jinahya.bouncycastle.crypto.JinahyaCrypto;
import io.github.jinahya.bouncycastle.crypto.modes.JinahyaAEADCipherUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;

/**
 * Utilities for the {@value _SEED__Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaSEEDUtils {

    // ------------------------------------------------------------------------------------------------ CBC/PKCS5Padding
    private static byte[] _CBC_PKCS5Padding(final byte[] key, final byte[] iv, final byte[] in,
                                            final boolean forEncryption) {
        _SEED__Utils.requireValidKey(key);
        _SEED__Utils.requireValidIv(iv);
        Objects.requireNonNull(in, "in is null");
        final var cipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(new SEEDEngine()),
                new PKCS7Padding()
        );
        final var params = new ParametersWithIV(
                new KeyParameter(key),
                iv
        );
        cipher.init(forEncryption, params);
        final var out = new byte[cipher.getOutputSize(in.length)];
        try {
            final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(cipher, in, 0, in.length, out, 0);
            return Arrays.copyOf(out, outlen);
        } catch (final InvalidCipherTextException itce) {
            throw new RuntimeException("failed to process/finalize", itce);
        }
    }

    private static JinahyaCrypto _CBC_PKCS5Padding(final byte[] key, final byte[] iv) {
        _SEED__Utils.requireValidKey(key);
        _SEED__Utils.requireValidIv(iv);
        final var cipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(new SEEDEngine()),
                new PKCS7Padding()
        );
        final var params = new ParametersWithIV(
                new KeyParameter(key),
                iv
        );
        return new JinahyaBufferedBlockCipherCrypto(cipher, params);
    }

    /**
     * Encrypts, using specified key and iv, specified input bytes, and returns the result.
     *
     * @param key the key.
     * @param iv  the iv.
     * @param in  the input bytes to encrypt.
     * @return an array of encrypted bytes.
     */
    public static byte[] encrypt_CBC_PKCS5Padding(final byte[] key, final byte[] iv, final byte[] in) {
        return _CBC_PKCS5Padding(key, iv)
                .encrypt(in);
    }

    /**
     * Decrypts, using specified key and iv, specified input bytes, and returns the result.
     *
     * @param key the key.
     * @param iv  the iv.
     * @param in  the input bytes to decrypt.
     * @return an array of decrypted bytes.
     */
    public static byte[] decrypt_CBC_PKCS5Padding(final byte[] key, final byte[] iv, final byte[] in) {
        return _CBC_PKCS5Padding(key, iv)
                .decrypt(in);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static long _CBC_PKCS5Padding(final byte[] key, final byte[] iv, final InputStream in,
                                          final OutputStream out, final int inlen, final boolean forEncryption)
            throws IOException {
        _SEED__Utils.requireValidKey(key);
        _SEED__Utils.requireValidIv(iv);
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (inlen <= 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is not positive");
        }
        final var cipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(new SEEDEngine()),
                new PKCS7Padding()
        );
        final var params = new ParametersWithIV(
                new KeyParameter(key),
                iv
        );
        cipher.init(forEncryption, params);
        final var inbuf = new byte[inlen];
        final var outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        try {
            return JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(cipher, in, out, inbuf, outbuf);
        } catch (final InvalidCipherTextException itce) {
            throw new RuntimeException("failed to process/finalize", itce);
        }
    }

    private static JinahyaCrypto _CBC_PKCS5Padding(final byte[] key, final byte[] iv, final InputStream in) {
        _SEED__Utils.requireValidKey(key);
        _SEED__Utils.requireValidIv(iv);
        Objects.requireNonNull(in, "in is null");
        final var cipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(new SEEDEngine()),
                new PKCS7Padding()
        );
        final var params = new ParametersWithIV(
                new KeyParameter(key),
                iv
        );
        return new JinahyaBufferedBlockCipherCrypto(cipher, params);
    }

    /**
     * Encrypts, using specified key and iv, all bytes from specified input stream, and writes encrypted bytes to
     * specified output stream.
     *
     * @param key   the key.
     * @param iv    the iv.
     * @param in    the input stream from which plain bytes are read.
     * @param out   the output stream to which encrypted bytes are written.
     * @param inlen a length of an internal buffer for reading bytes from the input stream; should be positive.
     * @return the number of bytes written to the output stream.
     * @throws IOException if an I/O error occurs.
     */
    public static long encrypt_CBC_PKCS5Padding(final byte[] key, final byte[] iv, final InputStream in,
                                                final OutputStream out, final int inlen)
            throws IOException {
        return _CBC_PKCS5Padding(key, iv)
                .encrypt(in, out, new byte[inlen]);
    }

    /**
     * Decrypts, using specified key and iv, all bytes from specified input stream, and writes decrypted bytes to
     * specified output stream.
     *
     * @param key   the key.
     * @param iv    the iv.
     * @param in    the input stream from which encrypted bytes are read.
     * @param out   the output stream to which decrypted bytes are written.
     * @param inlen a length of an internal buffer for reading bytes from the input stream; should be positive.
     * @return the number of bytes written to the output stream.
     * @throws IOException if an I/O error occurs.
     */
    public static long decrypt_CBC_PKCS5Padding(final byte[] key, final byte[] iv, final InputStream in,
                                                final OutputStream out, final int inlen)
            throws IOException {
        return _CBC_PKCS5Padding(key, iv, in)
                .decrypt(in, out, new byte[inlen]);
    }

    // -------------------------------------------------------------------------------------------------- /GCM/NoPadding
    private static byte[] _GCM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                         final byte[] in, final boolean forEncryption) {
        _SEED__Utils.requireValidKey(key);
        __GCM_Utils.requireValid_tLen_GCM(tLen);
        __GCM_Utils.requireValid_iv_GCM(iv);
        Objects.requireNonNull(in, "in is null");
        final var cipher = GCMBlockCipher.newInstance(new SEEDEngine());
        final var params = new AEADParameters(
                new KeyParameter(key),
                tLen,
                iv,
                aad
        );
        cipher.init(forEncryption, params);
        final var out = new byte[cipher.getOutputSize(in.length)];
        try {
            final var outlen = JinahyaAEADCipherUtils.processBytesAndDoFinal(cipher, in, 0, in.length, out, 0);
            return Arrays.copyOf(out, outlen);
        } catch (final InvalidCipherTextException itce) {
            throw new RuntimeException("failed to process/finalize", itce);
        }
    }

    /**
     * Encrypts specified input bytes, in {@code GCM} mode with no padding, and returns result.
     *
     * @param key  a key.
     * @param tLen a length (in bits) of authentication tag.
     * @param iv   an initialization vector whose length should be greater than or equals to
     *             {@value __GCM_Constants#IV_SIZE_GCM_MINIMUM}.
     * @param aad  an additional authenticated data. may be {@code null}.
     * @param in   the input bytes to encrypt.
     * @return an array of encrypted bytes.
     */
    public static byte[] encrypt_GCM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                               final byte[] in) {
        return _GCM_NoPadding(key, tLen, iv, aad, in, true);
    }

    /**
     * Decrypts specified input bytes, in {@code GCM} mode with no padding, and returns result.
     *
     * @param key  a key.
     * @param tLen a length (in bits) of authentication tag.
     * @param iv   an initialization vector whose length should be greater than or equals to
     *             {@value __GCM_Constants#IV_SIZE_GCM_MINIMUM}.
     * @param aad  an additional authenticated data. may be {@code null}.
     * @param in   the input bytes to decrypt.
     * @return an array of decrypted bytes.
     */
    public static byte[] decrypt_GCM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                               final byte[] in) {
        return _GCM_NoPadding(key, tLen, iv, aad, in, false);
    }

    private static long _GCM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                       final InputStream in, final OutputStream out, final int inlen,
                                       final boolean forEncryption)
            throws IOException {
        _SEED__Utils.requireValidKey(key);
        __GCM_Utils.requireValid_tLen_GCM(tLen);
        __GCM_Utils.requireValid_iv_GCM(iv);
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (inlen <= 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is not positive");
        }
        final var cipher = GCMBlockCipher.newInstance(new SEEDEngine());
        final var params = new AEADParameters(
                new KeyParameter(key),
                tLen,
                iv,
                aad
        );
        cipher.init(forEncryption, params);
        final var inbuf = new byte[inlen];
        final var outbuf = new byte[cipher.getOutputSize(inbuf.length)];
        try {
            return JinahyaAEADCipherUtils.processAllBytesAndDoFinal(cipher, in, out, inbuf, 0, inbuf.length, outbuf);
        } catch (final InvalidCipherTextException itce) {
            throw new RuntimeException("failed to process/finalize", itce);
        }
    }

    /**
     * Encrypts all bytes from specified input stream, and writes encrypted bytes to specified output stream.
     *
     * @param key   the key.
     * @param tLen  a length (in bits) of authentication tag.
     * @param iv    an initialization vector whose length should be greater than or equals to
     *              {@value __GCM_Constants#IV_SIZE_GCM_MINIMUM}.
     * @param aad   an additional authenticated data. may be {@code null}.
     * @param in    the input stream from which plain bytes are read.
     * @param out   the output stream to which encrypted bytes are written.
     * @param inlen a length of an internal buffer for reading bytes from the input stream; should be positive.
     * @return the number of bytes written to the output stream.
     * @throws IOException if an I/O error occurs.
     */
    public static long encrypt_GMM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                             final InputStream in, final OutputStream out, final int inlen)
            throws IOException {
        return _GCM_NoPadding(key, tLen, iv, aad, in, out, inlen, true);
    }

    /**
     * Decrypts all bytes from specified input stream, and writes decrypted bytes to specified output stream.
     *
     * @param key   the key.
     * @param tLen  a length (in bits) of authentication tag.
     * @param iv    an initialization vector whose length should be greater than or equals to
     *              {@value __GCM_Constants#IV_SIZE_GCM_MINIMUM}.
     * @param aad   an additional authenticated data. may be {@code null}.
     * @param in    the input stream from which plain bytes are read.
     * @param out   the output stream to which decrypted bytes are written.
     * @param inlen a length of an internal buffer for reading bytes from the input stream; should be positive.
     * @return the number of bytes written to the output stream.
     * @throws IOException if an I/O error occurs.
     */
    public static long decrypt_GMM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                             final InputStream in, final OutputStream out, final int inlen)
            throws IOException {
        return _GCM_NoPadding(key, tLen, iv, aad, in, out, inlen, false);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaSEEDUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
