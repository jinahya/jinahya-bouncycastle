package io.github.jinahya.bouncycastle.miscellaneous;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.junit.jupiter.params.provider.Arguments;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public final class _RSA___TestUtils {

    public static IntStream getKeySizeStream() {
        return IntStream.of(
                1024,
                2048,
                3072
        );
    }

    public static Stream<Arguments> getKeySizeAndAsymmetricCipherKeyPairArgumentsStream() {
        return _RSA___TestUtils.getKeySizeStream().mapToObj(ks -> {
//            final var params = new RSAKeyGenerationParameters(
//                    new BigInteger("10001", 16),
//                    _Random_TestUtils.random(),
//                    ks,
//                    80
//            );
//            final var generator = new RSAKeyPairGenerator();
//            generator.init(params);
//            final var keyPair = generator.generateKeyPair();
            final var keyPair = generateKeyPair(ks);
            return Arguments.of(ks, keyPair);
        });
    }

    // https://stackoverflow.com/a/49163162/330457
    public static AsymmetricCipherKeyPair generateKeyPair(final int keySize) {
        final KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance(_RSA___Constants.ALGORITHM);
        } catch (final NoSuchAlgorithmException nsae) {
            throw new RuntimeException(nsae);
        }
        generator.initialize(keySize);
        final var keyPair = generator.generateKeyPair();
        final var publicKey = (RSAPublicKey) keyPair.getPublic();
        final var publicParam = new RSAKeyParameters(false, publicKey.getModulus(), publicKey.getPublicExponent());
        if (keyPair.getPrivate() instanceof RSAPrivateCrtKey crtKey) {
            final var privateParam = new RSAPrivateCrtKeyParameters(
                    crtKey.getModulus(),
                    crtKey.getPublicExponent(),
                    crtKey.getPrivateExponent(),
                    crtKey.getPrimeP(),
                    crtKey.getPrimeQ(),
                    crtKey.getPrimeExponentP(),
                    crtKey.getPrimeExponentQ(),
                    crtKey.getCrtCoefficient()
            );
            return new AsymmetricCipherKeyPair(publicParam, privateParam);
        } else {
            final var privateKey = (RSAPrivateKey) keyPair.getPrivate();
            final var privateParam = new RSAKeyParameters(
                    true,
                    privateKey.getModulus(),
                    privateKey.getPrivateExponent()
            );
            return new AsymmetricCipherKeyPair(publicParam, privateParam);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA___TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
