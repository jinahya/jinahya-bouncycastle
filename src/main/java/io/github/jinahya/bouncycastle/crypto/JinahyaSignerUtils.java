package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * Utilities for {@link Signer} interface.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaSignerUtils {

    private static <T extends Signer> T initFor(final T signer, final boolean forSigning,
                                                final CipherParameters params) {
        Objects.requireNonNull(signer, "signer is null");
        Objects.requireNonNull(params, "params is null");
        signer.init(forSigning, params);
        return signer;
    }

    /**
     * Initialize specified signer, for generating signature, with specified parameters.
     *
     * @param signer the signer to initialize.
     * @param params the params.
     * @param <T>    signer type parameter.
     * @return given {@code signer}.
     */
    public static <T extends Signer> T initForSigning(final T signer, final CipherParameters params) {
        return initFor(signer, true, params);
    }

    /**
     * Initialize specified signer, for generating signature, with specified key pair's private key.
     *
     * @param signer  the signer to initialize.
     * @param keyPair the key pair whose {@link AsymmetricCipherKeyPair#getPrivate() private key} is used for the
     *                initialization.
     * @param <T>     signer type parameter.
     * @return given {@code signer}.
     */
    public static <T extends Signer> T initForSigning(final T signer, final AsymmetricCipherKeyPair keyPair) {
        Objects.requireNonNull(keyPair, "keyPair is null");
        return initFor(signer, true, keyPair.getPrivate());
    }

    /**
     * Initialize specified signer, for verifying signature, with specified parameters.
     *
     * @param signer the signer to initialize.
     * @param params the params.
     * @param <T>    signer type parameter.
     * @return given {@code signer}.
     */
    public static <T extends Signer> T initForVerifying(final T signer, final CipherParameters params) {
        return initFor(signer, false, params);
    }

    /**
     * Initialize specified signer, for verifying signature, with specified key pair's public key.
     *
     * @param signer  the signer to initialize
     * @param keyPair the key pair whose {@link AsymmetricCipherKeyPair#getPublic() public key} is used for the
     *                initialization.
     * @param <T>     signer type parameter.
     * @return given {@code signer}.
     */
    public static <T extends Signer> T initForVerifying(final T signer, final AsymmetricCipherKeyPair keyPair) {
        Objects.requireNonNull(keyPair, "keyPair is null");
        return initForVerifying(signer, keyPair.getPublic());
    }

    // -----------------------------------------------------------------------------------------------------------------
    static void validate(final Signer signer, final byte[] in) {
        Objects.requireNonNull(signer, "signer is null");
        Objects.requireNonNull(in, "in is null");
    }

    public static int generateSignature(final Signer signer, final byte[] in, final int inoff, final int inlen,
                                        final byte[] out, final int outoff)
            throws CryptoException {
        Objects.requireNonNull(signer, "signer is null");
        Objects.requireNonNull(in, "in is null");
        validate(signer, in);
        return JinahyaSignerUtils_.generateSignature(signer, in, inoff, inlen, out, outoff);
    }

    public static boolean verifySignature(final Signer signer, final byte[] in, final int inoff, final int inlen,
                                          final byte[] signature) {
        validate(signer, in);
        Objects.requireNonNull(signature, "signature is null");
        return JinahyaSignerUtils_.verifySignature(signer, in, inoff, inlen, signature);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static int generateSignature(final Signer signer, final InputStream in, final byte[] inbuf,
                                        final byte[] out, final int outoff)
            throws IOException, CryptoException {
        Objects.requireNonNull(signer, "signer is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(inbuf, "inbuf is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if (outoff > out.length) {
            throw new IllegalArgumentException("outoff(" + outoff + ") > out.length(" + out.length + ")");
        }
        return JinahyaSignerUtils_.generateSignature(signer, in, inbuf, out, outoff);
    }

    public static boolean verifySignature(final Signer signer, final InputStream in, final byte[] inbuf,
                                          final byte[] signature)
            throws IOException {
        Objects.requireNonNull(signature, "signature is null");
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        Objects.requireNonNull(signature, "signature is null");
        return JinahyaSignerUtils_.verifySignature(signer, in, inbuf, signature);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static void validate(final Signer signer, final ByteBuffer input, final ByteBuffer signature) {
        Objects.requireNonNull(signer, "signer is null");
        Objects.requireNonNull(input, "in is null");
        Objects.requireNonNull(signer, "signer is null");
    }

    public static int generateSignature(final Signer signer, final ByteBuffer input, final ByteBuffer signature)
            throws CryptoException {
        validate(signer, input, signature);
        return JinahyaSignerUtils_.generateSignature(signer, input, signature);
    }

    public static boolean verifySignature(final Signer signer, final ByteBuffer input, final ByteBuffer signature) {
        validate(signer, input, signature);
        return JinahyaSignerUtils_.verifySignature(signer, input, signature);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static void validate(final Signer signer, final InputStream in, final byte[] inbuf, final ByteBuffer signature) {
        Objects.requireNonNull(signer, "signer is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(inbuf, "inbuf is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        Objects.requireNonNull(signature, "signature is null");
    }

    public static int generateSignature(final Signer signer, final InputStream in, final byte[] inbuf,
                                        final ByteBuffer signature)
            throws IOException, CryptoException {
        validate(signer, in, inbuf, signature);
        return JinahyaSignerUtils_.generateSignature(signer, in, inbuf, signature);
    }

    public static boolean verifySignature(final Signer signer, final InputStream in, final byte[] inbuf,
                                          final ByteBuffer signature)
            throws IOException {
        validate(signer, in, inbuf, signature);
        Objects.requireNonNull(signature, "signature is null");
        return JinahyaSignerUtils_.verifySignature(signer, in, inbuf, signature);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaSignerUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
