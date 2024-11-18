package io.github.jinahya.bouncycastle.miscellaneous;

import org.bouncycastle.crypto.Digest;

import java.util.Objects;

public final class _RSA_Utils {

    /**
     * Returns the maximum value of {@code mLen} for specified {@code k} in <a
     * href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.2">RSAES-PKCS1-v1_5</a> encryption scheme.
     *
     * @param k the length in octets of the modulus n
     * @return the maximum octet string of length {@code mLen} for {@code k}.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.2">7.2.  RSAES-PKCS1-v1_5</a> (RFC 8017:
     * PKCS #1: RSA Cryptography Specifications Version 2.2)
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.2.1">7.2.1.  Encryption Operation</a> (RFC
     * 8017: PKCS #1: RSA Cryptography Specifications Version 2.2)
     */
    public static int max_mLen_RSAES_PKCS1_v1_5(final int k) {
        return k - 11; // mLen <= k - 11
    }

    /**
     * Returns the maximum value of {@code mLen} for specified {@code k} and specified hash output length, in <a
     * href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.1">RSAES-OAEP</a> encryption scheme.
     *
     * @param k    the length in octets of the RSA modulus n.
     * @param hLen output length in octets of hash function Hash.
     * @return the maximum octet string of length {@code mLen} for {@code k} and {@code hLen}.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.1">7.1.  RSAES-OAEP</a> (RFC 8017:
     * PKCS #1: RSA Cryptography Specifications Version 2.2)
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1">7.1.1.  Encryption Operation</a> (RFC
     * 8017: PKCS #1: RSA Cryptography Specifications Version 2.2)
     * @see _RSA_Constants#H_LEN_SHA1
     * @see _RSA_Constants#H_LEN_SHA256
     */
    public static int max_mLen_RSAES_OAEP(final int k, final int hLen) {
        return k - (hLen << 1) - 2; // mLen <= k - 2hLen - 2
    }

    /**
     * Returns the maximum value of {@code mLen} for specified {@code k} and specified digest's
     * {@link Digest#getDigestSize() digest size}, in <a
     * href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.1">RSAES-OAEP</a> encryption scheme.
     *
     * @param k      the length in octets of the RSA modulus n.
     * @param digest the digest whose {@link Digest#getDigestSize() digest size} is used for the {@code hLen}.
     * @return the maximum octet string of length {@code mLen} for {@code k} and {@code digest.digestSize}.
     * @see #max_mLen_RSAES_OAEP(int, int)
     */
    public static int max_mLen_RSAES_OAEP(final int k, final Digest digest) {
        Objects.requireNonNull(digest, "digest is null");
        return max_mLen_RSAES_OAEP(k, digest.getDigestSize());
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
