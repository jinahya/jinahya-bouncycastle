package _examples.message_digest;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

/**
 * A class for testing {@link MessageDigest}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@Slf4j
class MessageDigestTest {

    // https://docs.oracle.com/en/java/javase/23/docs/specs/security/standard-names.html#messagedigest-algorithms
    private static final List<String> ALGORITHM_NAMES = List.of(
            "MD2",
            "MD5",
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
    );

    private static Stream<String> getAlgorithmNameStream() {
        return ALGORITHM_NAMES.stream();
    }

    private static final List<String> PROVIDER_NAMES = List.of(
            "SUN",
            "BC"
    );

    private static Stream<Arguments> getAlgorithmNameAndProviderNameArgumentsStream() {
        return ALGORITHM_NAMES.stream().flatMap(a -> {
            return PROVIDER_NAMES.stream().map(p -> Arguments.of(a, p));
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    @BeforeAll
    static void addBouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getAlgorithmNameStream"})
    @ParameterizedTest
    void __empty(final String algorithm) throws NoSuchProviderException {
        final var input = new byte[0];
        log.debug("    input: [{}] ({} bytes)", HexFormat.of().formatHex(input), input.length);
        for (final var provider : PROVIDER_NAMES) {
            final MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(algorithm, provider);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get instance for {}, {}", algorithm, provider, nsae);
                continue;
            }
            log.debug("algorithm: {}, provider: {}", digest.getAlgorithm(), digest.getProvider());
            final var result = digest.digest(input);
            log.debug("   result: [{}] ({} bits)", HexFormat.of().formatHex(result), result.length << 3);
        }
    }

    @MethodSource({"getAlgorithmNameStream"})
    @ParameterizedTest
    void __random(final String algorithm) throws NoSuchProviderException {
        final var input = new byte[ThreadLocalRandom.current().nextInt(32)];
        ThreadLocalRandom.current().nextBytes(input);
        log.debug("    input: [{}] ({} bytes)", HexFormat.of().formatHex(input), input.length);
        for (final var provider : PROVIDER_NAMES) {
            final MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(algorithm, provider);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get instance for {}, {}", algorithm, provider, nsae);
                continue;
            }
            log.debug("algorithm: {}, provider: {}", digest.getAlgorithm(), digest.getProvider());
            final var result = digest.digest(input);
            log.debug("   result: [{}] ({} bits)", HexFormat.of().formatHex(result), result.length << 3);
        }
    }

    @MethodSource({"getAlgorithmNameStream"})
    @ParameterizedTest
    void __random(final String algorithm, @TempDir final File tempDir) throws IOException, NoSuchProviderException {
        final var file = File.createTempFile("tmp", null, tempDir);
        try (var stream = new FileOutputStream(file)) {
            final var input = new byte[ThreadLocalRandom.current().nextInt(8192)];
            ThreadLocalRandom.current().nextBytes(input);
            stream.write(input);
            stream.flush();
        }
        log.debug("    input: {} bytes", file.length());
        for (final var provider : PROVIDER_NAMES) {
            final MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(algorithm, provider);
            } catch (final NoSuchAlgorithmException nsae) {
                log.error("failed to get instance for {}, {}", algorithm, provider, nsae);
                continue;
            }
            log.debug("algorithm: {}, provider: {}", digest.getAlgorithm(), digest.getProvider());
            try (var stream = new FileInputStream(file)) {
                final var b = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
                for (int r; (r = stream.read(b)) != -1; ) {
                    digest.update(b, 0, r);
                }
                final var result = digest.digest();
                log.debug("   result: [{}] ({} bits)", HexFormat.of().formatHex(result), result.length << 3);
            }
        }
    }

    // https://en.wikipedia.org/wiki/Avalanche_effect
    @MethodSource({"getAlgorithmNameAndProviderNameArgumentsStream"})
    @ParameterizedTest
    void __avalanche(final String algorithm, final String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        final var input = new byte[ThreadLocalRandom.current().nextInt(32) + 1];
        ThreadLocalRandom.current().nextBytes(input);
        log.debug("    input: [{}] ({} bytes)", HexFormat.of().formatHex(input), input.length);
        {
            final var digest = MessageDigest.getInstance(algorithm, provider);
            log.debug("algorithm: {}, provider: {}", digest.getAlgorithm(), digest.getProvider());
            final var result = digest.digest(input);
            log.debug("   result: [{}] ({} bits)", HexFormat.of().formatHex(result), result.length << 3);
        }
        log.debug("-------------------------------------------------------------------- randomizing the last byte..." );
        input[input.length - 1] = (byte) ThreadLocalRandom.current().nextInt();
        {
            log.debug("    input: [{}] ({} bytes)", HexFormat.of().formatHex(input), input.length);
            final var digest = MessageDigest.getInstance(algorithm, provider);
            log.debug("algorithm: {}, provider: {}", digest.getAlgorithm(), digest.getProvider());
            final var result = digest.digest(input);
            log.debug("   result: [{}] ({} bits)", HexFormat.of().formatHex(result), result.length << 3);
        }
    }
}
