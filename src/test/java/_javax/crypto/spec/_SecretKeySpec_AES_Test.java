package _javax.crypto.spec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

class _SecretKeySpec_AES_Test {

    private static final String ALGORITHM = "AES";

    @ValueSource(ints = {
            128,
            192,
            256
    })
    @ParameterizedTest
    void __(final int keySize) throws NoSuchAlgorithmException {
        final var key = new byte[keySize >> 3];
        SecureRandom.getInstanceStrong().nextBytes(key);
        final var secretKey = new SecretKeySpec(key, ALGORITHM);
    }
}
