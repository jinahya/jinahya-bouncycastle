package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
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
    private void validate(final byte[] in) {
        assert in != null;
        final var inputBlockSize = cipher.getInputBlockSize();
        if (in.length > inputBlockSize) {
            throw new IllegalArgumentException(
                    "in.length(" + in.length + ") > cipher.inputBlockSize(" + inputBlockSize + ")"
            );
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public byte[] encrypt(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        initForEncryption();
        validate(in);
        final var out = new byte[cipher.getOutputBlockSize()];
        try {
            final var outlen = JinahyaAsymmetricBlockCipherUtils_.processBlock(
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
        JinahyaAsymmetricBlockCipherUtils.validateNonNull(cipher, input, output);
        try {
            return JinahyaAsymmetricBlockCipherUtils_.processBlock(
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
        validate(in);
        final var out = new byte[cipher.getOutputBlockSize()];
        try {
            final var outlen = JinahyaAsymmetricBlockCipherUtils_.processBlock(
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
    public int decrypt(final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        initForDecryption();
        JinahyaAsymmetricBlockCipherUtils.validateNonNull(cipher, input, output);
        try {
            return JinahyaAsymmetricBlockCipherUtils_.processBlock(
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
        final var outbuf = new byte[cipher.getOutputBlockSize()];
        try {
            return JinahyaAsymmetricBlockCipherUtils_.processAllBytes(cipher, in, out, inbuf, outbuf);
        } catch (final InvalidCipherTextException e) {
            throw JinahyaCryptoException.ofEncryptionFailure(e);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        Objects.requireNonNull(inbuf, "inbuf is null");
        initForDecryption();
        final var inputBlockSize = cipher.getInputBlockSize();
        if (Objects.requireNonNull(inbuf, "inbuf is null").length < inputBlockSize) {
            throw new IllegalArgumentException(
                    "inbuf.length(" + inbuf.length + " < cipher.inputBlockSize(" + inputBlockSize + ")"
            );
        }
        final var outbuf = new byte[cipher.getOutputBlockSize()];
        try {
            return JinahyaAsymmetricBlockCipherUtils_.processAllBytes(cipher, in, out, inbuf, outbuf);
        } catch (final InvalidCipherTextException e) {
            throw JinahyaCryptoException.ofEncryptionFailure(e);
        }
    }
}
