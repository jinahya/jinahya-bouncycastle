package io.github.jinahya.bouncycastle.crypto;

import __asymmetric._RSA__TestUtils;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.junit.jupiter.params.provider.Arguments;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.stream.Stream;

final class JinahyaAsymmetricBlockCipher_TestUtils {

    private static final SecureRandom SECURE_RANDOM;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstanceStrong();
        } catch (final NoSuchAlgorithmException nsae) {
            throw new ExceptionInInitializerError(nsae.getMessage());
        }
    }

    public static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
        return _RSA__TestUtils.getKeySizeStream().mapToObj(ks -> {
            final var params = new RSAKeyGenerationParameters(
                    new BigInteger("10001", 16),
                    SECURE_RANDOM,
                    ks,
                    80
            );
            final var generator = new RSAKeyPairGenerator();
            generator.init(params);
            final var keyPair = generator.generateKeyPair();
            return Arguments.of(ks, keyPair);
        });
    }

    private JinahyaAsymmetricBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}