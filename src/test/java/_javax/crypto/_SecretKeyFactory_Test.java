package _javax.crypto;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ThreadLocalRandom;

@Slf4j
class _SecretKeyFactory_Test {

    // -----------------------------------------------------------------------------------------------------------------
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("providers and algorithms")
    @Test
    void providersAndAlgorithms() {
        final var type = SecretKeyFactory.class.getSimpleName();
        for (final var provider : Security.getProviders()) {
            for (final var service : provider.getServices()) {
                if (!type.equalsIgnoreCase(service.getType())) {
                    continue;
                }
                final var algorithm = service.getAlgorithm();
                log.debug("provider: {}, algorithm: {}", provider.getName(), algorithm);
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @_SecretKeyFactory_Test_Utils.ParameterizedTestWithStandardAlgorithmAndProvider
    void __(final String algorithm, final Provider provider) {
        final SecretKeyFactory instance;
        try {
            instance = SecretKeyFactory.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException nsae) {
            log.error("failed to get instance for {} with {}", algorithm, provider, nsae);
            return;
        }
        log.debug("algorithm: {}, provider: {}", instance.getAlgorithm(), instance.getProvider());
        if (algorithm.equalsIgnoreCase("AES")) {
            final var key = new byte[128];
            ThreadLocalRandom.current().nextBytes(key);
            try {
                final var secretKey = instance.generateSecret(new SecretKeySpec(key, algorithm));
            } catch (final InvalidKeySpecException ikse) {
                throw new RuntimeException(ikse);
            }
        }
    }
}
