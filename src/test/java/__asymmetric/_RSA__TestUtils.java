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
    // k -> mLen
    private static final Map<Integer, Integer> M_LEN_RSAES_PKCS1_v1_5 = new WeakHashMap<>() {{
        put(new Integer(128), 117);
        put(new Integer(256), 245);
        put(new Integer(384), 373);
    }};

    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.2.1
    public static int mLen_RSAES_PKCS1_v1_5(final int keyBytes) {
        if (true) {
            return keyBytes - 11; // mLen <= k - 11
        }
        return M_LEN_RSAES_PKCS1_v1_5.computeIfAbsent(new Integer(keyBytes), k -> {
            return k - 11; // mLen <= k - 11
        });
    }

    // hLen -> k -> mLen
    private static final Map<Integer, Map<Integer, Integer>> M_LEN_RSAES_OAEP = new WeakHashMap<>() {{
        put(new Integer(20), new WeakHashMap<>() {{
            put(new Integer(128), 86);
            put(new Integer(256), 214);
            put(new Integer(384), 342);
        }});
        put(new Integer(32), new WeakHashMap<>() {{
            put(new Integer(128), 62);
            put(new Integer(256), 190);
            put(new Integer(384), 318);
        }});
    }};

    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
    public static int mLen_RSAES_OAEP(final int keyBytes, final int hLen) {
        if (true) {
            return keyBytes - (hLen << 1) - 1; // mLen <= k - 2hLen - 2
        }
        return M_LEN_RSAES_OAEP.computeIfAbsent(new Integer(hLen), WeakHashMap::new)
                .computeIfAbsent(new Integer(keyBytes), k -> {
                    return k - (hLen << 1) - 2; // mLen <= k - 2hLen - 2
                });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA__TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
