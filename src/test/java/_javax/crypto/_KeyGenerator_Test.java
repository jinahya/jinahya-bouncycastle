package _javax.crypto;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.HexFormat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class _KeyGenerator_Test {

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
    @DisplayName("generateKey")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithStandardAlgorithmAndProvider
    void generateKey__(final String algorithm, final Provider provider, final TestReporter reporter) {
        final KeyGenerator instance;
        try {
            instance = KeyGenerator.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException nsae) {
            log.error("failed to get instance for {} with {}", algorithm, provider, nsae);
            return;
        }
        // -------------------------------------------------------------------------------------------------------------
        final var key = instance.generateKey();
        // -------------------------------------------------------------------------------------------------------------
        reporter.publishEntry("algorithm", key.getAlgorithm());
        final var encoded = key.getEncoded();
        reporter.publishEntry(String.format("encoded(%1$d)", encoded.length), HexFormat.of().formatHex(encoded));
    }

    @DisplayName("generateKey(AES)")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithProvider
    void generateKey__AES(final Provider provider, final TestReporter reporter) {
        final var algorithm = "AES";
        final KeyGenerator instance;
        try {
            instance = KeyGenerator.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException nsae) {
            log.error("failed to get instance for {} with {}", algorithm, provider, nsae);
            return;
        }
        for (final var keysize : new int[]{128, 192, 256}) {
            reporter.publishEntry("keysize", Integer.toString(keysize));
            try {
                instance.init(keysize);
            } catch (final InvalidParameterException ipe) {
                log.error("failed to init with keysize({})", keysize, ipe);
                continue;
            }
            // -------------------------------------------------------------------------------------------------------------
            final var key = instance.generateKey();
            // -------------------------------------------------------------------------------------------------------------
            reporter.publishEntry("algorithm", key.getAlgorithm());
            final var encoded = key.getEncoded();
            reporter.publishEntry(String.format("encoded(%1$d)", encoded.length), HexFormat.of().formatHex(encoded));
        }
    }

    @DisplayName("generateKey(DESede)")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithProvider
    void generateKey__DESede(final Provider provider, final TestReporter reporter) {
        final var algorithm = "DESede";
        final KeyGenerator instance;
        try {
            instance = KeyGenerator.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException nsae) {
            log.error("failed to get instance for {} with {}", algorithm, provider, nsae);
            return;
        }
        for (final var keysize : new int[]{112, 168}) {
            reporter.publishEntry("keysize", Integer.toString(keysize));
            try {
                instance.init(keysize);
            } catch (final InvalidParameterException ipe) {
                log.error("failed to init with keysize({})", keysize, ipe);
                continue;
            }
            // -------------------------------------------------------------------------------------------------------------
            final var key = instance.generateKey();
            // -------------------------------------------------------------------------------------------------------------
            reporter.publishEntry("algorithm", key.getAlgorithm());
            final var encoded = key.getEncoded();
            reporter.publishEntry(String.format("encoded(%1$d)", encoded.length), HexFormat.of().formatHex(encoded));
        }
    }

    @DisplayName("generateKey(HmacSHA1)")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithProvider
    void generateKey__HmacSHA1(final Provider provider, final TestReporter reporter) {
        final var algorithm = "HmacSHA1";
        final KeyGenerator instance;
        try {
            instance = KeyGenerator.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException nsae) {
            log.error("failed to get instance for {} with {}", algorithm, provider, nsae);
            return;
        }
        // -------------------------------------------------------------------------------------------------------------
        final var key = instance.generateKey();
        // -------------------------------------------------------------------------------------------------------------
        reporter.publishEntry("algorithm", key.getAlgorithm());
        final var encoded = key.getEncoded();
        reporter.publishEntry(String.format("encoded(%1$d)", encoded.length), HexFormat.of().formatHex(encoded));
    }

    @DisplayName("generateKey(HmacSHA256)")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithProvider
    void generateKey__HmacSHA256(final Provider provider, final TestReporter reporter) {
        final var algorithm = "HmacSHA256";
        final KeyGenerator instance;
        try {
            instance = KeyGenerator.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException nsae) {
            log.error("failed to get instance for {} with {}", algorithm, provider, nsae);
            return;
        }
        // -------------------------------------------------------------------------------------------------------------
        final var key = instance.generateKey();
        // -------------------------------------------------------------------------------------------------------------
        reporter.publishEntry("algorithm", key.getAlgorithm());
        final var encoded = key.getEncoded();
        reporter.publishEntry(String.format("encoded(%1$d)", encoded.length), HexFormat.of().formatHex(encoded));
    }
}
