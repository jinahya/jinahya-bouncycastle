package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * A crypto for a {@link AsymmetricBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaAsymmetricBlockCipherUtils
 */
public class JinahyaAsymmetricBlockCipherCrypto
        extends JinahyaCipherCrypto<AsymmetricBlockCipher> {

    /**
     * Creates a new instance with specified cipher and the public key of specified key pair.
     *
     * @param cipher  the cipher.
     * @param keyPair the key pair whose {@link AsymmetricCipherKeyPair#getPublic() public key} is used for the
     *                {@link #params} arguments.
     * @return a new instance.
     * @see AsymmetricCipherKeyPair#getPublic()
     * @see JinahyaAsymmetricBlockCipherCrypto#JinahyaAsymmetricBlockCipherCrypto(AsymmetricBlockCipher,
     * CipherParameters)
     */
    public static JinahyaAsymmetricBlockCipherCrypto withPublicKeyOf(final AsymmetricBlockCipher cipher,
                                                                     final AsymmetricCipherKeyPair keyPair) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(keyPair, "keyPair is null");
        return new JinahyaAsymmetricBlockCipherCrypto(cipher, keyPair.getPublic());
    }

    /**
     * Creates a new instance with specified cipher and the private key of specified key pair.
     *
     * @param cipher  the cipher.
     * @param keyPair the key pair whose {@link AsymmetricCipherKeyPair#getPrivate() private key} is used for the
     *                {@link #params} arguments.
     * @return a new instance.
     * @see AsymmetricCipherKeyPair#getPrivate()
     * @see JinahyaAsymmetricBlockCipherCrypto#JinahyaAsymmetricBlockCipherCrypto(AsymmetricBlockCipher,
     * CipherParameters)
     */
    public static JinahyaAsymmetricBlockCipherCrypto withPrivateKeyOf(final AsymmetricBlockCipher cipher,
                                                                      final AsymmetricCipherKeyPair keyPair) {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(keyPair, "keyPair is null");
        return new JinahyaAsymmetricBlockCipherCrypto(cipher, keyPair.getPrivate());
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Creates a new instance with specified cipher and cipher parameters.
     *
     * @param cipher the cipher.
     * @param params the cipher parameters.
     * @see #withPublicKeyOf(AsymmetricBlockCipher, AsymmetricCipherKeyPair)
     * @see #withPrivateKeyOf(AsymmetricBlockCipher, AsymmetricCipherKeyPair)
     */
    public JinahyaAsymmetricBlockCipherCrypto(final AsymmetricBlockCipher cipher, final CipherParameters params) {
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
        final var inblocks = in.length / cipher.getInputBlockSize();
        final var out = new byte[inblocks * cipher.getOutputBlockSize()];
        try {
            final var outblocks = JinahyaAsymmetricBlockCipherUtils_.processBlocks(
                    cipher,
                    in,
                    0,
                    in.length,
                    out,
                    0
            );
            assert outblocks == inblocks;
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
        return out;
    }

    @Override
    public int encrypt(final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        initForEncryption();
        try {
            return JinahyaAsymmetricBlockCipherUtils_.processBlocks(
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
        final var inblocks = in.length / cipher.getInputBlockSize();
        final var out = new byte[inblocks * cipher.getOutputBlockSize()];
        try {
            final var outblocks = JinahyaAsymmetricBlockCipherUtils_.processBlocks(
                    cipher,
                    in,
                    0,
                    in.length,
                    out,
                    0
            );
            assert outblocks == inblocks;
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
        return out;
    }

    @Override
    public int decrypt(final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        initForDecryption();
        try {
            return JinahyaAsymmetricBlockCipherUtils_.processBlocks(
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
        Objects.requireNonNull(inbuf, "inbuf is null");
        initForEncryption();
        if (inbuf.length < cipher.getInputBlockSize()) {
            throw new IllegalArgumentException(
                    "inbuf.length(" + inbuf.length + " < cipher.inputBlockSize(" + cipher.getInputBlockSize() + ")"
            );
        }
        try {
            return JinahyaAsymmetricBlockCipherUtils_.processAllBlocks(
                    cipher,
                    in,
                    out,
                    inbuf
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
        Objects.requireNonNull(inbuf, "inbuf is null");
        initForDecryption();
        if (inbuf.length < cipher.getInputBlockSize()) {
            throw new IllegalArgumentException(
                    "inbuf.length(" + inbuf.length + " < cipher.inputBlockSize(" + cipher.getInputBlockSize() + ")"
            );
        }
        try {
            return JinahyaAsymmetricBlockCipherUtils_.processAllBlocks(
                    cipher,
                    in,
                    out,
                    inbuf
            );
        } catch (final InvalidCipherTextException icte) {
            throw JinahyaCryptoException.ofEncryptionFailure(icte);
        }
    }
}
