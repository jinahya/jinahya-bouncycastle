package io.github.jinahya.bouncycastle.miscellaneous;

public final class _RSA_Utils {

    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.2.1
    public static int mLen_RSAES_PKCS1_v1_5(final int keyBytes) {
        return keyBytes - 11; // mLen <= k - 11
    }

    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
    public static int mLen_RSAES_OAEP(final int keyBytes, final int hLen) {
        return keyBytes - (hLen << 1) - 2; // mLen <= k - 2hLen - 2
    }
//
//    // ----------------------------------------------------------------------------------------------- RSASSA-PKCS1-v1_5
//    // https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.1
//    public static byte[] RSASSA_PKCS1_V1_5_SIGN(final Digest digest, final RSAKeyParameters params,
//                                                final byte[] message)
//            throws CryptoException {
//        Objects.requireNonNull(digest, "digest is null");
//        if (!Objects.requireNonNull(params, "params is null").isPrivate()) {
//            throw new IllegalArgumentException("params is not a private key: " + params);
//        }
//        Objects.requireNonNull(message, "message is null");
//        final var signer = new RSADigestSigner(digest);
//        signer.init(true, params);
//        signer.update(message, 0, message.length);
//        return signer.generateSignature();
//    }
//
//    // -----------------------------------------------------------------------------------------------------------------
//    // https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2
//    public static boolean RSASSA_PKCS1_V1_5_VERIFY(final Digest digest, final AsymmetricKeyParameter params,
//                                                   final byte[] message, final byte[] signature) {
//        Objects.requireNonNull(digest, "digest is null");
//        if (Objects.requireNonNull(params, "params is null").isPrivate()) {
//            throw new IllegalArgumentException("param is a private key: " + params);
//        }
//        Objects.requireNonNull(message, "message is null");
//        Objects.requireNonNull(signature, "signature is null");
//        final var signer = new RSADigestSigner(digest);
//        signer.init(false, params);
//        signer.update(message, 0, message.length);
//        return signer.verifySignature(signature);
//    }
//
//    public static boolean RSASSA_PKCS1_V1_5_VERIFY(final Digest digest, final AsymmetricCipherKeyPair keyPair,
//                                                   final byte[] message, final byte[] signature) {
//        Objects.requireNonNull(keyPair, "keyPair is null");
//        return RSASSA_PKCS1_V1_5_VERIFY(
//                digest,
//                keyPair.getPublic(),
//                message,
//                signature
//        );
//    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
