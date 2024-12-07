package _examples;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

import javax.crypto.Cipher;
import java.security.Security;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An abstract class for testing {@link javax.crypto.Cipher}.
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
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Slf4j
public abstract class _Cipher____Test {

    static final String PROVIDER_NAME_SUN_JCE = "SunJCE";

    protected static final String PROVIDER_NAME_BC = "BC";

    @BeforeAll
    static void doBeforeAll() {
        final var provider = new BouncyCastleProvider();
        assertThat(provider.getName()).isEqualTo(PROVIDER_NAME_BC);
        final var result = Security.addProvider(provider);
    }

    @AfterAll
    static void doAfterAll() {
//        Security.removeProvider("BC");
    }

    public static final List<String> PROVIDER_NAME_LIST = List.of(
            PROVIDER_NAME_SUN_JCE,
            PROVIDER_NAME_BC
    );

    protected static Cipher getCipherInstance(final String transformation, final String provider) throws Exception {
        final var cipher = Cipher.getInstance(transformation, provider);
        assertThat(cipher.getProvider().getName())
                .as("cipher.provider.name")
                .isEqualTo(provider);
        assertThat(cipher.getAlgorithm())
                .as("cipher.algorithm")
                .isEqualTo(transformation);
        return cipher;
    }
}
