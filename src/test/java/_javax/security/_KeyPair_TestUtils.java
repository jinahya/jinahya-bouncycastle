package _javax.security;

import __asymmetric._RSA__Constants;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public final class _KeyPair_TestUtils {

    public static KeyPair generateKeyPair(final String provider, final int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        final var generator = KeyPairGenerator.getInstance(_RSA__Constants.ALGORITHM, provider);
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    private _KeyPair_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
