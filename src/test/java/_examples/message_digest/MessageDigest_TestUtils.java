package _examples.message_digest;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.DynamicTest;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An abstract class for testing {@link Cipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @
 * @see <a href="https://docs.oracle.com/en/java/javase/23/docs/specs/security/standard-names.html">Java Security
 * Standard Algorithm Names</a> (Java / Java SE / 23)
 * @see <a href="https://docs.oracle.com/en/java/javase/23/security/index.html">Java Platform, Standard Edition /
 * Security Developer’s Guide / Release 23</a>
 * @see <a href="https://docs.oracle.com/en/java/javase/23/security/oracle-providers.html">Java Platform, Standard
 * Edition / Security Developer’s Guide / Release 23 / 4 JDK Providers Documentation</a>
 * @see <a
 * href="https://docs.oracle.com/en/java/javase/23/docs/api/java.base/javax/crypto/Cipher.html">javax.crypt.Cipher</a>
 * (Java / Java SE / 23)
 */
@Slf4j
public final class MessageDigest_TestUtils {

    private static final String PROVIDER_NAME_SUN = "SUN";

    private static final String PROVIDER_NAME_BC = "BC";

    static final List<String> PROVIDER_NAME_LIST = List.of(
            PROVIDER_NAME_SUN,
            PROVIDER_NAME_BC
    );

    // https://docs.oracle.com/en/java/javase/23/docs/api/java.base/java/security/MessageDigest.html
    static final List<String> DIGEST_ALGORITHM_LIST = List.of(
            "SHA-1",
            "SHA-256"
    );

    static Stream<MessageDigest> getMessageDigestStream(final String algorithm) {
        return PROVIDER_NAME_LIST.stream().map(pn -> {
            try {
                return MessageDigest.getInstance(algorithm, pn);
            } catch (final Exception e) {
                throw new RuntimeException("failed to create message digest for '" + algorithm + "' with '" + pn + "'",
                                           e);
            }
        });
    }

    static Stream<MessageDigest> getMessageDigestStream() {
        return PROVIDER_NAME_LIST.stream().flatMap(pn -> {
            return DIGEST_ALGORITHM_LIST.stream().map(da -> {
                try {
                    return MessageDigest.getInstance(da, pn);
                } catch (final Exception e) {
                    throw new RuntimeException("failed to create message digest for '" + da + "' with '" + pn + "'", e);
                }
            });
        });
    }

    static Stream<DynamicTest> getDynamicTestStream(final String algorithm, final byte[] input) {
        return PROVIDER_NAME_LIST.stream().map(pn -> DynamicTest.dynamicTest(pn, () -> {
            final MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(algorithm, pn);
            } catch (final Exception e) {
                log.error("failed to get digest instance for '" + algorithm + "' with '" + pn + "'" );
                return;
            }
            final var output = digest.digest(input);
            log.debug("output: ({}) {}", formatLength(output.length),
                      HexFormat.of().withUpperCase().formatHex(output));
        }));
    }

    static Stream<DynamicTest> getDynamicTestStream(final String algorithm, final File tempDir) throws IOException {
        final var file = File.createTempFile("tmp", null, tempDir);
        {
            final var bytes = new byte[ThreadLocalRandom.current().nextInt(8192)];
            ThreadLocalRandom.current().nextBytes(bytes);
            Files.write(file.toPath(), bytes);
        }
        log.debug("file.length: {}", file.length());
        return PROVIDER_NAME_LIST.stream().map(pn -> DynamicTest.dynamicTest(pn, () -> {
            final MessageDigest digest;
            try {
                digest = MessageDigest.getInstance(algorithm, pn);
            } catch (final Exception e) {
                log.error("failed to get digest instance for '" + algorithm + "' with '" + pn + "'" );
                return;
            }
            try (var input = new FileInputStream(file)) {
                final var buffer = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
                for (int r; (r = input.read(buffer)) != -1; ) {
                    digest.update(buffer, 0, r);
                }
                final var output = digest.digest();
                log.debug("output: ({}) {}", formatLength(output.length),
                          HexFormat.of().withUpperCase().formatHex(output));
            }
        }));
    }

    private static byte[] digest(final File file, final MessageDigest digest) {
        final var baos = new ByteArrayOutputStream();
        try (var input = new FileInputStream(file);
             final var output = new DigestOutputStream(baos, digest)) {
            final var bytes = IOUtils.copyLarge(input, output);
            assertThat(bytes).isEqualTo(file.length());
            output.flush();
        } catch (final IOException ioe) {
            throw new RuntimeException(ioe);
        }
        return baos.toByteArray();
    }

    public static void assertHaveSame(final File file1, final File file2) {
        getMessageDigestStream().forEach(d -> {
            final byte[] digest1 = digest(file1, d);
            d.reset();
            final byte[] digest2 = digest(file2, d);
            assertThat(digest2).isEqualTo(digest1);
        });
    }

    static String formatLength(final int length) {
        return String.format("%1$3d / %2$d", length, length << 3);
    }

    private MessageDigest_TestUtils() {
        throw new AssertionError("instantiation is not allowed" );
    }
}
