package io.github.jinahya.bouncycastle.miscellaneous;

import org.bouncycastle.crypto.Digest;

import java.util.Objects;

/**
 * Utilities for {@value _RSA___Constants#ALGORITHM} algorithm.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class _RSA___Utils {

    /**
     * Returns the maximum value of the {@code mLen} for specified {@code k} in <a
     * href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.2">RSAES-PKCS1-v1_5</a> encryption scheme.
     *
     * @param k the length in octets of the modulus {@code n}.
     * @return the maximum number of message octets can be encrypted, for {@code k}.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.2">7.2.  RSAES-PKCS1-v1_5</a> (RFC 8017:
     * PKCS #1: RSA Cryptography Specifications Version 2.2)
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.2.1">7.2.1.  Encryption Operation</a> (RFC
     * 8017: PKCS #1: RSA Cryptography Specifications Version 2.2)
     */
    public static int max_mLen_RSAES_PKCS1_v1_5(final int k) {
        return k - 11; // mLen <= k - 11
    }

    /**
     * Returns the maximum value of the {@code mLen} for specified {@code k} and specified hash output length, in <a
     * href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.1">RSAES-OAEP</a> encryption scheme.
     *
     * @param k    the length in octets of the RSA modulus {@code n}..
     * @param hLen the length in octets of the hash function output.
     * @return the maximum number of message octets can be encrypted, for {@code k} and {@code hLel}.
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.1">7.1.  RSAES-OAEP</a> (RFC 8017:
     * PKCS #1: RSA Cryptography Specifications Version 2.2)
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1">7.1.1.  Encryption Operation</a> (RFC
     * 8017: PKCS #1: RSA Cryptography Specifications Version 2.2)
     * @see _RSA___Constants#H_LEN_SHA1
     * @see _RSA___Constants#H_LEN_SHA256
     */
    public static int max_mLen_RSAES_OAEP(final int k, final int hLen) {
        return k - (hLen << 1) - 2; // mLen <= k - 2hLen - 2
    }

    /**
     * Returns the maximum value of the {@code mLen} for specified {@code k} and specified hash function's
     * {@link Digest#getDigestSize() digestSize}, in <a
     * href="https://datatracker.ietf.org/doc/html/rfc8017#section-7.1">RSAES-OAEP</a> encryption scheme.
     *
     * @param k    the length in octets of the RSA modulus {@code n}..
     * @param hash the hash function.
     * @return the maximum number of message octets can be encrypted, for {@code k} and {@code hash.digestSize}.
     * @see Digest#getDigestSize()
     * @see #max_mLen_RSAES_OAEP(int, int)
     */
    public static int max_mLen_RSAES_OAEP(final int k, final Digest hash) {
        Objects.requireNonNull(hash, "hash is null");
        return max_mLen_RSAES_OAEP(k, hash.getDigestSize());
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA___Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
