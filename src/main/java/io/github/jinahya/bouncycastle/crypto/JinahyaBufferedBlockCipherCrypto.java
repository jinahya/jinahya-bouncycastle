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

/**
 * A crypto for a {@link BufferedBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaBufferedBlockCipherUtils
 */
public class JinahyaBufferedBlockCipherCrypto
        extends JinahyaCipherCrypto<BufferedBlockCipher> {

    public JinahyaBufferedBlockCipherCrypto(final BufferedBlockCipher cipher, final CipherParameters params) {
        super(cipher, params);
    }

    // ---------------------------------------------------------------------------------------------------------- cipher
    @Override
    protected void initFor(final boolean encryption) {
        cipher.init(encryption, params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public byte[] encrypt(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        initForEncryption();
        final var out = new byte[cipher.getOutputSize(in.length)];
        try {
            final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal_(
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

    @Override
    public int encrypt(final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        initForEncryption();
        try {
            return JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal_(
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
    public byte[] decrypt(byte[] in) {
        Objects.requireNonNull(in, "in is null");
        initForDecryption();
        final var out = new byte[cipher.getOutputSize(in.length)];
        try {
            final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal_(
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
    public int decrypt(final ByteBuffer input, final ByteBuffer output) {
        initForDecryption();
        try {
            return JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal_(
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
    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        initForEncryption();
        try {
            return JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal_(
                    cipher,
                    in,
                    out,
                    inbuf,
                    null
            );
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        initForDecryption();
        try {
            return JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal_(
                    cipher,
                    in,
                    out,
                    inbuf,
                    null
            );
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofDecryptionFailure(icte);
        }
    }
}
