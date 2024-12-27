package _javax.crypto;

import _java.security._Provider__Test_Utils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class _Mac_Test {

    // -----------------------------------------------------------------------------------------------------------------
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("providers and algorithms")
    @Test
    void providersAndAlgorithms() {
        _Provider__Test_Utils.getServiceStream(Mac.class.getSimpleName()).forEach(s -> {
            final var algorithm = s.getAlgorithm();
            final var provider = s.getProvider();
            log.debug("provider: {}, algorithm: {}", provider.getName(), algorithm);
        });
    }

    @DisplayName("PBEWith<mac>")
    @Test
    void __PBEWith() {
        _Provider__Test_Utils.getServiceStream(Mac.class.getSimpleName()).forEach(s -> {
            final var algorithm = s.getAlgorithm();
            if (!algorithm.startsWith("PBEWith")) {
                return;
            }
            final var provider = s.getProvider();
            log.debug("provider: {}, algorithm: {}", provider, algorithm);
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("getInstance(algorithm, provider)")
    @_Mac_Test_Utils.ParameterizedTestWithStandardAlgorithmsAndProviders
    void getInstance__(final String algorithm, final Provider provider) {
        // -------------------------------------------------------------------------------------------------------- when
        final Mac instance;
        try {
            instance = Mac.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException nsae) {
            log.error("failed to get instance with {}, {}", algorithm, provider, nsae);
            return;
        }
        log.debug("algorithm: {}, provider: {}", instance.getAlgorithm(), instance.getProvider());
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(instance.getAlgorithm()).isEqualTo(algorithm);
        assertThat(instance.getProvider()).isSameAs(provider);
    }

    @DisplayName("HmacSHA1")
    @_Mac_Test_Utils.ParameterizedTestWithProviders
    void __HmacSHA1(final Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        final var algorithm = "HmacSHA1";
        final var mac = Mac.getInstance(algorithm, provider);
        final var key = KeyGenerator.getInstance(algorithm, provider).generateKey();
        log.debug("key.length: {}", key.getEncoded().length);
        mac.init(key);
        final var input = new byte[ThreadLocalRandom.current().nextInt(8192)];
        ThreadLocalRandom.current().nextBytes(input);
        // ----------------------------------------------------------------------------------------------------------- 1
        mac.update(input);
        final var finalized1 = mac.doFinal();
        log.debug("finalized1({}): {}", finalized1.length, HexFormat.of().formatHex(finalized1));
        // ----------------------------------------------------------------------------------------------------------- 2
        final var finalized2 = mac.doFinal(input);
        log.debug("finalized2({}): {}", finalized2.length, HexFormat.of().formatHex(finalized2));
        // -------------------------------------------------------------------------------------------------------------
        assertThat(finalized2).isEqualTo(finalized1);
    }

    @DisplayName("HmacSHA256")
    @_Mac_Test_Utils.ParameterizedTestWithProviders
    void __HmacSHA256(final Provider provider) throws NoSuchAlgorithmException, InvalidKeyException {
        final var algorithm = "HmacSHA256";
        final var mac = Mac.getInstance(algorithm, provider);
        final var key = KeyGenerator.getInstance(algorithm, provider).generateKey();
        log.debug("key.length: {}", key.getEncoded().length);
        mac.init(key);
        final var input = new byte[ThreadLocalRandom.current().nextInt(8192)];
        ThreadLocalRandom.current().nextBytes(input);
        // ----------------------------------------------------------------------------------------------------------- 1
        mac.update(input);
        final var finalized1 = mac.doFinal();
        log.debug("finalized1({}): {}", finalized1.length, HexFormat.of().formatHex(finalized1));
        // ----------------------------------------------------------------------------------------------------------- 2
        final var finalized2 = mac.doFinal(input);
        log.debug("finalized2({}): {}", finalized2.length, HexFormat.of().formatHex(finalized2));
        // -------------------------------------------------------------------------------------------------------------
        assertThat(finalized2).isEqualTo(finalized1);
    }
}
