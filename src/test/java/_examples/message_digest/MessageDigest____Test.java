package _examples.message_digest;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;

import java.security.Security;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
abstract class MessageDigest____Test {

    @BeforeAll
    static void addBouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    static String formatLength(final int length) {
        return String.format("%1$3d / %2$d", length, length << 3);
    }
}
