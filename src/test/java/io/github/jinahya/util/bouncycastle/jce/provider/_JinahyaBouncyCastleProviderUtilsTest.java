package io.github.jinahya.util.bouncycastle.jce.provider;

import io.github.jinahya.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;

@Slf4j
class _JinahyaBouncyCastleProviderUtilsTest {

    @Test
    void addBouncyCastleProvider__() {
        assertThatCode(JinahyaBouncyCastleProviderUtils::addBouncyCastleProvider).doesNotThrowAnyException();
        assertThatCode(JinahyaBouncyCastleProviderUtils::addBouncyCastleProvider).doesNotThrowAnyException();
    }

    @Disabled
    @Test
    void removeBouncyCastleProvider__() {
//        assertThatCode(JinahyaBouncyCastleProviderUtils::removeBouncyCastleProvider).doesNotThrowAnyException();
//        assertThatCode(JinahyaBouncyCastleProviderUtils::removeBouncyCastleProvider).doesNotThrowAnyException();
    }

    @Disabled
    @Test
    void __() {
//        assertThatCode(JinahyaBouncyCastleProviderUtils::addBouncyCastleProvider).doesNotThrowAnyException();
//        assertThatCode(JinahyaBouncyCastleProviderUtils::removeBouncyCastleProvider).doesNotThrowAnyException();
    }
}