package _org.bouncycastle.jce.provider;

import _java.security._Provider__Test;
import io.github.jinahya.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class _BouncyCastleProvider_Test {

    @Test
    void __() {
        final var provider = JinahyaBouncyCastleProviderUtils.newBouncyCastleProvider();
        _Provider__Test.logProvider(provider);
    }
}
