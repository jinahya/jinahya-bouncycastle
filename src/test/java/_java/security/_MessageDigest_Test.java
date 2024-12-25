package _java.security;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.aggregator.AggregateWith;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class _MessageDigest_Test {

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
}
