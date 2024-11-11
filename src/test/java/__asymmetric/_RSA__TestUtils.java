package __asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.stream.IntStream;

public final class _RSA__TestUtils {

    public static IntStream getKeySizeStream() {
        return IntStream.of(
                1024,
                2048
        );
    }

    public static KeyPair generateKeyPair(final String provider, final int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        final var generator = KeyPairGenerator.getInstance(_RSA__Constants.ALGORITHM, provider);
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    public static void generateKeyPair(final KeyPair keyPair) {

    }

    private _RSA__TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
