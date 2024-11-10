package _javax.security;

import lombok.extern.slf4j.Slf4j;

import java.security.KeyPair;
import java.security.Signature;
import java.util.Objects;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public final class _Signature_Tests {

    public static Stream<String> getAlgorithmStream() {
        return Stream.of(
                "SHA1withDSA",
                "SHA256withDSA",
                "SHA1withRSA",
                "SHA256withRSA"
        );
    }

    // ------------------------------------------------------------------------------------------------------------- RSA
    public static Stream<String> getRsaAlgorithmStream() {
        return Stream.of(
                "SHA1withRSA",
                "SHA256withRSA",
                // -----------------------------------------------------------------------------------------------------
                "SHA1withRSA",
                "SHA224withRSA",
                "SHA256withRSA",
                "SHA384withRSA",
                "SHA512withRSA",
                "SHA512/224withRSA",
                "SHA512/256withRSA",
                "SHA3-224withRSA",
                "SHA3-256withRSA",
                "SHA3-384withRSA",
                "SHA3-512withRSA"
        );
    }

    public static Stream<Signature> getRsaSignatureStream(final String provider) {
        return getRsaAlgorithmStream().map(a -> {
            try {
                return Signature.getInstance(a, provider);
            } catch (final Exception e) {
                log.error("failed to get Signature instance; algorithm: '{}', provider: '{}'", a, provider, e);
                return null;
            }
        }).filter(Objects::nonNull);
    }

    public static void verifyRsa(final byte[] plain, final KeyPair keyPair) {
        Objects.requireNonNull(plain, "plain is null");
        Objects.requireNonNull(keyPair, "keyPair is null");
        Stream.of("SunRsaSign", "BC").forEach(p -> {
            _javax.security._Signature_Tests.getRsaSignatureStream(p).forEach(s -> {
                log.debug("signature: {} ({})", s.getAlgorithm(), s.getProvider().getName());
                try {
                    // -------------------------------------------------------------------------------------------- sign
                    s.initSign(keyPair.getPrivate());
                    s.update(plain);
                    final var signature = s.sign();
                    // ------------------------------------------------------------------------------------------ verify
                    s.initVerify(keyPair.getPublic());
                    s.update(plain);
                    final var verified = s.verify(signature);
                    // -------------------------------------------------------------------------------------------- then
                    assertThat(verified)
                            .as("verification result")
                            .isTrue();
                } catch (final Exception e) {
                    throw new RuntimeException(e);
                }
            });
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _Signature_Tests() {
        throw new AssertionError("instantiation is not allowed");
    }
}
