package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntConsumer;

/**
 * A crypto for a {@link BufferedBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaBufferedBlockCipherUtils
 */
public class JinahyaBufferedBlockCipherCrypto
        extends JinahyaCipherCrypto<BufferedBlockCipher> {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Creates a new instance with specified cipher and initialization parameters.
     *
     * @param cipher the cipher.
     * @param params the initialization parameters for the {@code cipher}.
     * @see JinahyaCipherCrypto#JinahyaCipherCrypto(Object, CipherParameters)
     */
    public JinahyaBufferedBlockCipherCrypto(final BufferedBlockCipher cipher, final CipherParameters params) {
        super(cipher, params);
    }

    // ---------------------------------------------------------------------------------------------------------- cipher
    @Override
    protected void initFor(final boolean encryption) {
        cipher.init(encryption, params);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * @param in the input bytes to encrypt.
     * @return {@inheritDoc}
     * @see JinahyaBufferedBlockCipherUtils#processBytesAndDoFinal(BufferedBlockCipher, byte[], int, int, byte[], int)
     */
    @Override
    protected byte[] encrypt_(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        initForEncryption();
        final var out = new byte[cipher.getOutputSize(in.length)];
        try {
            final var outlen = JinahyaBufferedBlockCipherUtils_.processBytesAndDoFinal(
                    cipher,
                    in,
                    0,
                    in.length,
                    out,
                    0
            );
            return Arrays.copyOf(out, outlen);
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @param input  the input buffer whose remaining bytes are encrypted.
     * @param output the output buffer onto which encrypted bytes are put.
     * @return {@inheritDoc}
     * @see JinahyaBufferedBlockCipherUtils#processBytesAndDoFinal(BufferedBlockCipher, ByteBuffer, ByteBuffer)
     */
    @Override
    protected int encrypt_(final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        initForEncryption();
        try {
            return JinahyaBufferedBlockCipherUtils_.processBytesAndDoFinal(
                    cipher,
                    input,
                    output
            );
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    protected byte[] decrypt_(byte[] in) {
        Objects.requireNonNull(in, "in is null");
        initForDecryption();
        final var out = new byte[cipher.getOutputSize(in.length)];
        try {
            final var outlen = JinahyaBufferedBlockCipherUtils_.processBytesAndDoFinal(
                    cipher,
                    in,
                    0,
                    in.length,
                    out,
                    0
            );
            return Arrays.copyOf(out, outlen);
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofDecryptionFailure(icte);
        }
    }

    @Override
    protected int decrypt_(final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        initForDecryption();
        try {
            return JinahyaBufferedBlockCipherUtils_.processBytesAndDoFinal(
                    cipher,
                    input,
                    output
            );
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    protected long encrypt_(final InputStream in, final OutputStream out, final byte[] inbuf,
                            final IntConsumer inlenconsumer,
                            final Function<? super byte[], ? extends IntConsumer> outbuffunction)
            throws IOException {
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        initForEncryption();
        try {
            return JinahyaBufferedBlockCipherUtils_.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    inbuf,
                    null,
                    inlenconsumer,
                    outbuffunction
            );
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    protected long decrypt_(InputStream in, OutputStream out, byte[] inbuf, IntConsumer inlenconsumer,
                            Function<? super byte[], ? extends IntConsumer> outbuffunction)
            throws IOException {
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        initForDecryption();
        try {
            return JinahyaBufferedBlockCipherUtils_.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    inbuf,
                    null,
                    inlenconsumer,
                    outbuffunction
            );
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofDecryptionFailure(icte);
        }
    }
}
