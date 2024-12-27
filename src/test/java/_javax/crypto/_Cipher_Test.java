package _javax.crypto;

import _java.security._Provider__Test_Utils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.security.Provider;
import java.security.Security;

import static org.assertj.core.api.Assertions.assertThatCode;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class _Cipher_Test {

    // -----------------------------------------------------------------------------------------------------------------
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("providers and algorithms")
    @Test
    void providersAndAlgorithms() {
        _Provider__Test_Utils.getServiceStream(_Cipher_Test_Constants.SERVICE_TYPE).forEach(s -> {
            final var algorithm = s.getAlgorithm();
            final var provider = s.getProvider();
            log.debug("provider: {}, algorithm: {}", provider, algorithm);
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("getInstance(transformation, provider)")
    @_Cipher_Test_Utils.ParameterizedTestWithProvidersAndSupportedTransformations
    void __(final Provider provider, final String transformation) {
        assertThatCode(() -> {
            Cipher.getInstance(transformation, provider);
        }).doesNotThrowAnyException();
    }
}
