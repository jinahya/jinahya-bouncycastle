package _java.security;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.aggregator.AggregateWith;
import org.junit.jupiter.params.converter.ArgumentConversionException;
import org.junit.jupiter.params.converter.ArgumentConverter;
import org.junit.jupiter.params.converter.ConvertWith;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class _MessageDigest_Test {

    static class HexToBytesArgumentConverter
            implements ArgumentConverter {

        @Override
        public Object convert(final Object source, final ParameterContext context) throws ArgumentConversionException {
            if (source == null) {
                return null;
            }
            return HexFormat.of().parseHex(String.valueOf(source));
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("providers and algorithms")
    @Test
    void providersAndAlgorithms() {
        _MessageDigest_Test_Utils.getServiceStream().forEach(s -> {
            final var algorithm = s.getAlgorithm();
            final var provider = s.getProvider();
            log.debug("provider: {}, algorithm: {}", provider.getName(), algorithm);
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private byte[] logInput(final byte[] input) {
        log.debug("    input: [{}] ({} byte(s))", HexFormat.of().formatHex(input), input.length);
        return input;
    }

    private File logInput(final File input) {
        log.debug("    input: {} bytes", input.length());
        return input;
    }

    private MessageDigest logDigest(final MessageDigest digest) {
        log.debug("algorithm: {}, provider: {}", digest.getAlgorithm(), digest.getProvider());
        return digest;
    }

    private byte[] logResult(final byte[] result) {
        log.debug("   result: [{}] ({} bits)", HexFormat.of().formatHex(result), result.length << 3);
        return result;
    }

    @DisplayName("empty bytes")
    @_MessageDigest_Test_Utils.ParameterizedTestWithStandardAlgorithmsAndProviderNames
    void __empty(final String algorithm, final String provider) {
        final var input = new byte[0];
        logInput(input);
        // -------------------------------------------------------------------------------------------------------------
        final MessageDigest instance;
        try {
            instance = MessageDigest.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
            log.error("failed to get instance for {}, {}", algorithm, provider, e);
            return;
        }
        logDigest(instance);
        final var result = instance.digest(input);
        logResult(result);
    }

    @DisplayName("random bytes")
    @_MessageDigest_Test_Utils.ParameterizedTestWithStandardAlgorithmsAndProviderNames
    void __random(final String algorithm, final String provider) {
        final var input = new byte[ThreadLocalRandom.current().nextInt(32) + 1];
        ThreadLocalRandom.current().nextBytes(input);
        logInput(input);
        // -------------------------------------------------------------------------------------------------------------
        final MessageDigest instance;
        try {
            instance = MessageDigest.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
            log.error("failed to get instance for {}, {}", algorithm, provider, e);
            return;
        }
        logDigest(instance);
        final var result = instance.digest(input);
        logResult(result);
    }

    @DisplayName("random bytes in a file")
    @_MessageDigest_Test_Utils.ParameterizedTestWithStandardAlgorithmsAndProviderNames
    void __random(final String algorithm, final String provider, @TempDir final File tempDir) throws IOException {
        final var file = File.createTempFile("tmp", null, tempDir);
        try (var stream = new FileOutputStream(file)) {
            final var input = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
            ThreadLocalRandom.current().nextBytes(input);
            stream.write(input);
            stream.flush();
        }
        logInput(file);
        // -------------------------------------------------------------------------------------------------------------
        final MessageDigest instance;
        try {
            instance = MessageDigest.getInstance(algorithm, provider);
        } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
            log.error("failed to get instance for {}, {}", algorithm, provider, e);
            return;
        }
        logDigest(instance);
        try (var stream = new FileInputStream(file)) {
            final var b = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
            for (int r; (r = stream.read(b)) != -1; ) {
                instance.update(b, 0, r);
            }
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
        final var result = instance.digest();
        logResult(result);
    }

    @DisplayName("avalanche effect")
    // https://en.wikipedia.org/wiki/Avalanche_effect
    @_MessageDigest_Test_Utils.ParameterizedTestWithMessageDigestInstance
    void __avalanche(
            @AggregateWith(_MessageDigest_Test_Utils.AlgorithmAndProviderArgumentsAggregator.class)
            final MessageDigest digest) {
        logDigest(digest);
        // -------------------------------------------------------------------------------------------------------------
        final var input = new byte[ThreadLocalRandom.current().nextInt(32) + 1];
        ThreadLocalRandom.current().nextBytes(input);
        logInput(input);
        {
            final var result = digest.digest(input);
            logResult(result);
        }
        // -------------------------------------------------------------------------------------------------------------
        final var index = ThreadLocalRandom.current().nextInt(input.length);
        log.debug("--------------- randomizing the byte at " + index + " (" + String.format("%2x", input[index]) + ')');
        input[index] = (byte) ThreadLocalRandom.current().nextInt();
        {
            logInput(input);
            digest.reset();
            final var result = digest.digest(input);
            logResult(result);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("other algorithms")
    @ValueSource(strings = {
            "RIPEMD128",
            "RIPEMD160",
            "RIPEMD256",
            "WHIRLPOOL"
    })
    @ParameterizedTest
    void __other(final String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        final var digest = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final var input = new byte[ThreadLocalRandom.current().nextInt(32) + 1];
        ThreadLocalRandom.current().nextBytes(input);
        logInput(input);
        // -------------------------------------------------------------------------------------------------------------
        final var result = digest.digest(input);
        logResult(result);
    }

    // https://en.wikipedia.org/wiki/SHA-2#Test_vectors
    @DisplayName("SHA-2")
    @Nested
    class SHA2Test {

        @CsvSource("SHA224, d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
        @CsvSource("SHA256, e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        @ParameterizedTest
        void __empty(final String algorithm, @ConvertWith(HexToBytesArgumentConverter.class) final byte[] expected)
                throws NoSuchAlgorithmException {
            final var instance = MessageDigest.getInstance(algorithm);
            final var actual = instance.digest(new byte[0]);
            assertThat(actual).isEqualTo(expected);
        }

        @ValueSource(strings = {
                "The quick brown fox jumps over the lazy dog",
                "The quick brown fox jumps over the lazy dog."
        })
        @ParameterizedTest
        void avalanche_effect(final String input, final TestReporter reporter) throws NoSuchAlgorithmException {
            final var instance = MessageDigest.getInstance("SHA224");
            final var actual = instance.digest(input.getBytes(StandardCharsets.US_ASCII));
            reporter.publishEntry(String.format("%-50s", input), HexFormat.of().formatHex(actual));
        }
    }
}
