package _java.security;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
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

import static _java.security._MessageDigest_Test_Utils.getProviderNameStream;

@Slf4j
class _MessageDigest_Test {

    // -----------------------------------------------------------------------------------------------------------------
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @DisplayName("providers and algorithms")
    @Test
    void algorithms() {
        for (final var provider : Security.getProviders()) {
            for (final var service : provider.getServices()) {
                if (!MessageDigest.class.getSimpleName().equalsIgnoreCase(service.getType())) {
                    continue;
                }
                final var algorithm = service.getAlgorithm();
                log.debug("provider: {}, algorithm: {}", provider.getName(), algorithm);
            }
        }
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

    @_MessageDigest_Test_Utils.ParameterizedTestWithStandardMessageDigestAlgorithms
    void __empty(final String algorithm) {
        final var input = new byte[0];
        logInput(input);
        // -------------------------------------------------------------------------------------------------------------
        getProviderNameStream().forEach(p -> {
            final MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(algorithm, p);
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                log.error("failed to get instance for {}, {}", algorithm, p, e);
                return;
            }
            logDigest(digest);
            final var result = digest.digest(input);
            logResult(result);
        });
    }

    @_MessageDigest_Test_Utils.ParameterizedTestWithStandardMessageDigestAlgorithms
    void __random(final String algorithm) {
        final var input = new byte[ThreadLocalRandom.current().nextInt(32) + 1];
        ThreadLocalRandom.current().nextBytes(input);
        logInput(input);
        // -------------------------------------------------------------------------------------------------------------
        getProviderNameStream().forEach(p -> {
            final MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(algorithm, p);
            } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
                log.error("failed to get instance for {}, {}", algorithm, p, e);
                return;
            }
            logDigest(digest);
            final var result = digest.digest(input);
            logResult(result);
        });
    }

    @_MessageDigest_Test_Utils.ParameterizedTestWithStandardMessageDigestAlgorithms
    void __random(final String algorithm, @TempDir final File tempDir) throws IOException {
        final var file = File.createTempFile("tmp", null, tempDir);
        try (var stream = new FileOutputStream(file)) {
            final var input = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
            ThreadLocalRandom.current().nextBytes(input);
            stream.write(input);
            stream.flush();
        }
        logInput(file);
        // -------------------------------------------------------------------------------------------------------------
        getProviderNameStream().forEach(p -> {
            final MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(algorithm, p);
            } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
                log.error("failed to get instance for {}, {}", algorithm, p, e);
                return;
            }
            logDigest(digest);
            try (var stream = new FileInputStream(file)) {
                final var b = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
                for (int r; (r = stream.read(b)) != -1; ) {
                    digest.update(b, 0, r);
                }
                final var result = digest.digest();
                logResult(result);
            } catch (final IOException ioe) {
                throw new RuntimeException(ioe);
            }
        });
    }

    // https://en.wikipedia.org/wiki/Avalanche_effect
    @_MessageDigest_Test_Utils.ParameterizedTestWithMessageDigest
    void __avalanche(final MessageDigest digest) {
        logDigest(digest);
        // -------------------------------------------------------------------------------------------------------------
        final var input = new byte[ThreadLocalRandom.current().nextInt(32) + 1];
        ThreadLocalRandom.current().nextBytes(input);
        logInput(input);
        {
            final var result = digest.digest(input);
            logResult(result);
        }
        log.debug("-------------------------------------------------------------------- randomizing the last byte...");
        input[input.length - 1] = (byte) ThreadLocalRandom.current().nextInt();
        {
            logInput(input);
            digest.reset();
            final var result = digest.digest(input);
            logResult(result);
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    @ValueSource(strings = {
            "RIPEMD128",
            "RIPEMD160",
            "RIPEMD256",
            "WHIRLPOOL"
    })
    @ParameterizedTest
    void __(final String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        final var digest = MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final var input = new byte[ThreadLocalRandom.current().nextInt(32) + 1];
        ThreadLocalRandom.current().nextBytes(input);
        logInput(input);
        // -------------------------------------------------------------------------------------------------------------
        final var result = digest.digest(input);
        logResult(result);
    }
}
