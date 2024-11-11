package io.github.jinahya.bouncycastle.miscellaneous;

import io.github.jinahya.bouncycastle.crypto.JinahyaBufferedBlockCipherUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Utilities for the {@value JinahyaSEEDUtils#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaSEEDUtils {

    /**
     * The name of the algorithm. The value is {@value}.
     */
    public static final String ALGORITHM = "SEED";

    /**
     * The block size of the {@value JinahyaSEEDUtils#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_BYTES
     */
    public static final int BLOCK_SIZE = 128;

    /**
     * The block size, in bytes, of the {@value JinahyaSEEDUtils#ALGORITHM} algorithm. The value is {@value}.
     *
     * @see #BLOCK_SIZE
     */
    public static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    /**
     * A list of allowed key sizes.
     */
    public static final List<Integer> ALLOWED_KEY_SIZES = List.of(
            128
    );

    /**
     * A list of allowed key sizes, in bytes.
     */
    public static final List<Integer> ALLOWED_KEY_BYTES =
            ALLOWED_KEY_SIZES.stream()
                    .map(ks -> ks >> 3)
                    .collect(Collectors.toUnmodifiableList());

    // -----------------------------------------------------------------------------------------------------------------
    private static byte[] requireValidKey(final byte[] key) {
        if (!ALLOWED_KEY_BYTES.contains(Objects.requireNonNull(key, "key is null").length)) {
            throw new IllegalArgumentException("key.length(" + key.length + ") is not allowed");
        }
        return key;
    }

    private static byte[] requireValidIv(final byte[] iv) {
        if (Objects.requireNonNull(iv, "iv is null").length != BLOCK_BYTES) {
            throw new IllegalArgumentException("iv.length(" + iv.length + ") != " + BLOCK_BYTES);
        }
        return iv;
    }

    // ------------------------------------------------------------------------------------------- SEED/CBC/PKCS5Padding
    private static byte[] _CBC_PKCS5Padding(final byte[] key, final byte[] iv, final byte[] in,
                                            final boolean forEncryption) {
        requireValidKey(key);
        requireValidIv(iv);
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

    /**
     * Encrypts, using specified key and iv, specified input bytes, and returns the result.
     *
     * @param key the key.
     * @param iv  the iv.
     * @param in  the input bytes to encrypt.
     * @return an array of encrypted bytes.
     */
    public static byte[] encrypt_CBC_PKCS5Padding(final byte[] key, final byte[] iv, final byte[] in) {
        return _CBC_PKCS5Padding(key, iv, in, true);
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
        return _CBC_PKCS5Padding(key, iv, in, false);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static long _CBC_PKCS5Padding(final byte[] key, final byte[] iv, final InputStream in,
                                          final OutputStream out, final int inlen, final boolean forEncryption)
            throws IOException {
        requireValidKey(key);
        requireValidIv(iv);
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
        return _CBC_PKCS5Padding(key, iv, in, out, inlen, true);
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
        return _CBC_PKCS5Padding(key, iv, in, out, inlen, false);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaSEEDUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
