package __asymmetric;

import _javax.security._Random_TestUtils;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.junit.jupiter.params.provider.Arguments;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class _RSA__TestUtils {

    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException nsae) {
            throw new ExceptionInInitializerError(nsae.getMessage());
        }
    }

    public static IntStream getKeySizeStream() {
        return IntStream.of(
                1024,
                2048,
                3072
        );
    }

    public static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
        return _RSA__TestUtils.getKeySizeStream().mapToObj(ks -> {
            final var params = new RSAKeyGenerationParameters(
                    new BigInteger("10001", 16),
                    _Random_TestUtils.random(),
                    ks,
                    80
            );
            final var generator = new RSAKeyPairGenerator();
            generator.init(params);
            final var keyPair = generator.generateKeyPair();
            return Arguments.of(ks, keyPair);
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static KeyPair generateKeyPair(final String provider, final int keySize)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        final var generator = KeyPairGenerator.getInstance(_RSA__Constants.ALGORITHM, provider);
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA__TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
