package __symmetric;

import io.github.jinahya.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class _JCEProviderTest {

    @BeforeAll
    public static void beforeAll() {
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
    }

    @AfterAll
    public static void afterAll() {
//        BouncyCastleProviderUtils.removeBouncyCastleProvider();
    }
}
