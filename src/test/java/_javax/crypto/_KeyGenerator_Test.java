package _javax.crypto;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;

import javax.crypto.KeyGenerator;
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
    @_KeyGenerator_Test_Utils.ParameterizedTestWithService
    void providersAndAlgorithms(final Provider.Service service) {
        final var algorithm = service.getAlgorithm();
        final var provider = service.getProvider();
        log.debug("provider: {}, algorithm: {}", provider, algorithm);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("generateKey")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithStandardAlgorithmsAndProviders
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
        reporter.publishEntry("key", key.toString());
        reporter.publishEntry("algorithm", key.getAlgorithm());
        final var encoded = key.getEncoded();
        reporter.publishEntry(String.format("encoded(%1$d)", encoded.length), HexFormat.of().formatHex(encoded));
    }

    // -----------------------------------------------------------------------------------------------------------------
    void generateKey__(final Provider provider, final String algorithm, final int... keysizes) {
        final KeyGenerator instance;
        try {
            instance = KeyGenerator.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException nsae) {
            log.error("failed to get instance for {} with {}", algorithm, provider, nsae);
            return;
        }
        for (final var keysize : keysizes) {
            log.debug("keysize: {}", keysize);
            try {
                instance.init(keysize);
            } catch (final InvalidParameterException ipe) {
                log.error("failed to init with keysize({})", keysize, ipe);
                continue;
            }
            // -------------------------------------------------------------------------------------------------------------
            final var key = instance.generateKey();
            // -------------------------------------------------------------------------------------------------------------
            log.debug("algorithm: {}", key.getAlgorithm());
            final var encoded = key.getEncoded();
            log.debug("encoded({}): {}", encoded.length, HexFormat.of().formatHex(encoded));
        }
    }

    @DisplayName("generateKey(AES)")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithProvider
    void generateKey__AES(final Provider provider) {
        generateKey__(provider, "AES", 128, 192, 256);
    }

    @DisplayName("generateKey(DESede)")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithProvider
    void generateKey__DESede(final Provider provider, final TestReporter reporter) {
        generateKey__(provider, "DESede", 112, 168);
    }

    // -----------------------------------------------------------------------------------------------------------------
    void generateKey__(final Provider provider, final String algorithm, final TestReporter reporter) {
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

    @DisplayName("generateKey(HmacSHA1)")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithProvider
    void generateKey__HmacSHA1(final Provider provider, final TestReporter reporter) {
        generateKey__(provider, "HmacSHA1", reporter);
    }

    @DisplayName("generateKey(HmacSHA256)")
    @_KeyGenerator_Test_Utils.ParameterizedTestWithProvider
    void generateKey__HmacSHA256(final Provider provider, final TestReporter reporter) {
        generateKey__(provider, "HmacSHA256", reporter);
    }
}
