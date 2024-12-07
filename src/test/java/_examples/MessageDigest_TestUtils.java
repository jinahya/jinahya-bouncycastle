package _examples;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.List;
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

    static final String PROVIDER_NAME_SUN = "SUN";

    static final String PROVIDER_NAME_BC = "BC";

    private static final List<String> PROVIDER_NAME_LIST = List.of(
            PROVIDER_NAME_SUN,
            PROVIDER_NAME_BC
    );

    // https://docs.oracle.com/en/java/javase/23/docs/api/java.base/java/security/MessageDigest.html
    private static final List<String> DIGEST_ALGORITHM_LIST = List.of(
            "SHA-1",
            "SHA-256"
    );

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

    private MessageDigest_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
