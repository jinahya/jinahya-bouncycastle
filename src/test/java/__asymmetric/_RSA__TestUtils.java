package __asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

public final class _RSA__TestUtils {

    public static IntStream getKeySizeStream() {
        return IntStream.of(
                1024,
                2048,
                3072
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

    // -----------------------------------------------------------------------------------------------------------------
    // k -> mLen
    private static final Map<Integer, Integer> M_LEN_RSAES_PKCS1_v1_5 = new HashMap<>() {{
        put(128, 117);
        put(256, 245);
        put(384, 318);
    }};

    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.2.1
    public static int mLen_RSAES_PKCS1_v1_5(final int keyBytes) {
        return M_LEN_RSAES_PKCS1_v1_5.computeIfAbsent(keyBytes, k -> {
            return k - 11; // mLen <= k - 11
        });
    }

    // hLen -> k -> mLen
    private static final Map<Integer, Map<Integer, Integer>> M_LEN_RSAES_OAEP = new HashMap<>() {{
        put(20, new HashMap<>() {{
            put(128, 86);
            put(256, 214);
            put(384, 342);
        }});
        put(32, new HashMap<>() {{
            put(128, 62);
            put(256, 190);
            put(384, 318);
        }});
    }};

    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
    public static int mLen_RSAES_OAEP(final int keyBytes, final int hLen) {
        return M_LEN_RSAES_OAEP.computeIfAbsent(hLen, HashMap::new)
                .computeIfAbsent(keyBytes, k -> {
                    return k - (hLen << 1) - 2; // mLen <= k - 2hLen - 2
                });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _RSA__TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
