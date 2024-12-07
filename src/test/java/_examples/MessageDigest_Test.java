package _examples;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.MessageDigest;
import java.security.Security;
import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

@Slf4j
class MessageDigest_Test {

    @BeforeAll
    static void addBouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    static Stream<Arguments> getMessageDigestStream() {
        return MessageDigest_TestUtils.getMessageDigestStream().map(d -> {
            return Arguments.of(Named.of(d.getProvider().getName() + ' ' + d.getAlgorithm(), d));
        });
    }

    @MethodSource({"getMessageDigestStream"})
    @ParameterizedTest
    void __empty(final MessageDigest digest) {
        final var input = new byte[0];
        ThreadLocalRandom.current().nextBytes(input);
        log.debug("input: ({}) {}", input.length, HexFormat.of().withUpperCase().formatHex(input));
        {
            final var output = digest.digest(input);
            log.debug("output: ({}) {}", output.length, HexFormat.of().withUpperCase().formatHex(output));
        }
        {
            final var output = digest.digest(input);
            log.debug("output: ({}) {}", output.length, HexFormat.of().withUpperCase().formatHex(output));
        }
    }

    @MethodSource({"getMessageDigestStream"})
    @ParameterizedTest
    void __(final MessageDigest digest) {
        final var input = new byte[ThreadLocalRandom.current().nextInt(16)];
        ThreadLocalRandom.current().nextBytes(input);
        log.debug("input: ({}) {}", input.length, HexFormat.of().withUpperCase().formatHex(input));
        {
            final var output = digest.digest(input);
            log.debug("output: ({}) {}", output.length, HexFormat.of().withUpperCase().formatHex(output));
        }
        {
            final var output = digest.digest(input);
            log.debug("output: ({}) {}", output.length, HexFormat.of().withUpperCase().formatHex(output));
        }
    }
}
