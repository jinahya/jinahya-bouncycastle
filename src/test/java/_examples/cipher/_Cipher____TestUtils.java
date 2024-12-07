package _examples.cipher;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;

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
public final class _Cipher____TestUtils {

    public static Cipher getCipherInstance(final String transformation, final String provider) throws Exception {
        final var cipher = Cipher.getInstance(transformation, provider);
        assertThat(cipher.getProvider().getName())
                .as("cipher.provider.name")
                .isEqualTo(provider);
        assertThat(cipher.getAlgorithm())
                .as("cipher.algorithm")
                .isEqualTo(transformation);
        return cipher;
    }

    private _Cipher____TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
