package io.github.jinahya.bouncycastle.miscellaneous;

import io.github.jinahya.bouncycastle.crypto.JinahyaCrypto;
import io.github.jinahya.bouncycastle.crypto.modes.JinahyaAEADCipherCrypto;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Function;
import java.util.function.IntConsumer;

/**
 * Utilities for the {@value _SEED___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class Jinahya_SEED_Utils {

//    // ----------------------------------------------------------------------------------------------- /CBC/PKCS7Padding
//    private static JinahyaCrypto _CBC_PKCS7Padding(final byte[] key, final byte[] iv) {
//        _SEED___Utils.requireValidKey(key);
//        __CBC__Utils.requireValidIv(iv, _SEED___Constants.BLOCK_BYTES);
//        final var cipher = new PaddedBufferedBlockCipher(
//                CBCBlockCipher.newInstance(new SEEDEngine()),
//                new PKCS7Padding()
//        );
//        final var params = new ParametersWithIV(
//                new KeyParameter(key),
//                iv
//        );
//        return new JinahyaBufferedBlockCipherCrypto(cipher, params);
//    }

    /**
     * Encrypts, in {@code CBC} mode with {@code PKCS7Padding}, using specified key and iv, specified input bytes, and
     * returns the result.
     *
     * @param key the key.
     * @param iv  the iv.
     * @param in  the input bytes to encrypt.
     * @return an array of encrypted bytes.
     */
    public static byte[] encrypt_CBC_PKCS7Padding(final byte[] key, final byte[] iv, final byte[] in) {
        return __CBC_PKCS7Padding_Utils.newJinahyaCrypto(key, iv, SEEDEngine::new)
                .encrypt(in);
    }

    /**
     * Decrypts, in {@code CBC} mode with {@code PKCS7Padding}, using specified key and iv, specified input bytes, and
     * returns the result.
     *
     * @param key the key.
     * @param iv  the iv.
     * @param in  the input bytes to encrypt.
     * @return an array of encrypted bytes.
     */
    public static byte[] decrypt_CBC_PKCS7Padding(final byte[] key, final byte[] iv, final byte[] in) {
        return __CBC_PKCS7Padding_Utils.newJinahyaCrypto(key, iv, SEEDEngine::new)
                .decrypt(in);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Encrypts, in {@value __CBC__Constants#MODE} mode with {@code PKCS7Padding}, using specified key and iv, all bytes
     * from specified input stream, and writes encrypted bytes to specified output stream.
     *
     * @param key            the key.
     * @param iv             the iv.
     * @param in             the input stream from which plain bytes are read.
     * @param out            the output stream to which encrypted bytes are written.
     * @param inbuf          a buffer for reading bytes from the input stream.
     * @return the number of bytes written to the output stream.
     * @throws IOException if an I/O error occurs.
     */
    public static long encrypt_CBC_PKCS7Padding(final byte[] key, final byte[] iv, final InputStream in,
                                                final OutputStream out, final byte[] inbuf,
                                                final IntConsumer inlenconsumer,
                                                final Function<? super byte[], ? extends IntConsumer> outbufconsumer)
            throws IOException {
        return __CBC_PKCS7Padding_Utils.newJinahyaCrypto(key, iv, SEEDEngine::new)
                .encrypt(in, out, inbuf);
    }

    /**
     * Decrypts, in {@value __CBC__Constants#MODE} mode with {@code PKCS7Padding}, using specified key and iv, all bytes
     * from specified input stream, and writes decrypted bytes to specified output stream.
     *
     * @param key            the key.
     * @param iv             the iv.
     * @param in             the input stream from which encrypted bytes are read.
     * @param out            the output stream to which decrypted bytes are written.
     * @param inbuf          a buffer for reading bytes from the input stream.
     * @return the number of bytes written to the output stream.
     * @throws IOException if an I/O error occurs.
     */
    public static long decrypt_CBC_PKCS7Padding(final byte[] key, final byte[] iv, final InputStream in,
                                                final OutputStream out, final byte[] inbuf,
                                                final IntConsumer inlenconsumer,
                                                final Function<? super byte[], ? extends IntConsumer> outbufconsumer)
            throws IOException {
        return __CBC_PKCS7Padding_Utils.newJinahyaCrypto(key, iv, SEEDEngine::new)
                .decrypt(in, out, inbuf);
    }

    // -------------------------------------------------------------------------------------------------- /GCM/NoPadding
    private static JinahyaCrypto _GCM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad) {
        _SEED___Utils.requireValidKey(key);
        __GCM__Utils.requireValid_tLen_GCM(tLen);
        __GCM__Utils.requireValid_iv_GCM(iv);
        final var cipher = GCMBlockCipher.newInstance(new SEEDEngine());
        final var params = new AEADParameters(
                new KeyParameter(key),
                tLen,
                iv,
                aad
        );
        return new JinahyaAEADCipherCrypto(cipher, params);
    }

    /**
     * Encrypts, in {@value __GCM__Constants#MODE} mode with no padding, specified input bytes, and returns result.
     *
     * @param key  a key.
     * @param tLen a length (in bits) of authentication tag.
     * @param iv   an initialization vector whose length should be greater than or equals to
     *             {@value __GCM__Constants#IV_SIZE_MINIMUM}.
     * @param aad  an additional authenticated data. may be {@code null}.
     * @param in   the input bytes to encrypt.
     * @return an array of encrypted bytes.
     */
    public static byte[] encrypt_GCM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                               final byte[] in) {
        return _GCM_NoPadding(key, tLen, iv, aad)
                .encrypt(in);
    }

    /**
     * Decrypts specified input bytes, in {@code GCM} mode with no padding, and returns result.
     *
     * @param key  a key.
     * @param tLen a length (in bits) of authentication tag.
     * @param iv   an initialization vector whose length should be greater than or equals to
     *             {@value __GCM__Constants#IV_SIZE_MINIMUM}.
     * @param aad  an additional authenticated data. may be {@code null}.
     * @param in   the input bytes to decrypt.
     * @return an array of decrypted bytes.
     */
    public static byte[] decrypt_GCM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                               final byte[] in) {
        return _GCM_NoPadding(key, tLen, iv, aad)
                .decrypt(in);
    }

    /**
     * Encrypts all bytes from specified input stream, and writes encrypted bytes to specified output stream.
     *
     * @param key            the key.
     * @param tLen           a length (in bits) of authentication tag.
     * @param iv             an initialization vector whose length should be greater than or equals to
     *                       {@value __GCM__Constants#IV_SIZE_MINIMUM}.
     * @param aad            an additional authenticated data. may be {@code null}.
     * @param in             the input stream from which plain bytes are read.
     * @param out            the output stream to which encrypted bytes are written.
     * @param inbuf          a buffer for reading bytes from the input stream.
     * @param inlenconsumer
     * @param outbufconsumer
     * @return the number of bytes written to the output stream.
     * @throws IOException if an I/O error occurs.
     */
    public static long encrypt_GMM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                             final InputStream in, final OutputStream out, final byte[] inbuf,
                                             final IntConsumer inlenconsumer,
                                             final Function<? super byte[], ? extends IntConsumer> outbufconsumer)
            throws IOException {
        return _GCM_NoPadding(key, tLen, iv, aad)
                .encrypt(in, out, inbuf);
    }

    /**
     * Decrypts all bytes from specified input stream, and writes decrypted bytes to specified output stream.
     *
     * @param key            the key.
     * @param tLen           a length (in bits) of authentication tag.
     * @param iv             an initialization vector whose length should be greater than or equals to
     *                       {@value __GCM__Constants#IV_SIZE_MINIMUM}.
     * @param aad            an additional authenticated data. may be {@code null}.
     * @param in             the input stream from which plain bytes are read.
     * @param out            the output stream to which decrypted bytes are written.
     * @param inbuf          a buffer for reading bytes from the input stream.
     * @param inlenconsumer
     * @param outbufconsumer
     * @return the number of bytes written to the output stream.
     * @throws IOException if an I/O error occurs.
     */
    public static long decrypt_GMM_NoPadding(final byte[] key, final int tLen, final byte[] iv, final byte[] aad,
                                             final InputStream in, final OutputStream out, final byte[] inbuf,
                                             final IntConsumer inlenconsumer,
                                             final Function<? super byte[], ? extends IntConsumer> outbufconsumer)
            throws IOException {
        return _GCM_NoPadding(key, tLen, iv, aad)
                .decrypt(in, out, inbuf);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private Jinahya_SEED_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
