package _javax.security;

import io.github.jinahya.bouncycastle.miscellaneous._RSA_Constants;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public final class _KeyPair_TestUtils {

    public static KeyPair generateKeyPair(final String provider, final int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        final var generator = KeyPairGenerator.getInstance(_RSA_Constants.ALGORITHM, provider);
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    public static KeyPair generateKeyPair_FIPS(final int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        final var generator = KeyPairGenerator.getInstance(_RSA_Constants.ALGORITHM, "FIPS");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    private _KeyPair_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
