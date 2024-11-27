package io.github.jinahya.util.bouncycastle.jce.provider;

import io.github.jinahya.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.util.HashSet;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@Slf4j
class _JinahyaBouncyCastleProviderUtilsTest {

    @Test
    void newBouncyCastleProvider__() {
        final var set = new HashSet<Provider>();
        assertThat(
                set.add(JinahyaBouncyCastleProviderUtils.newBouncyCastleProvider())
        ).isTrue();
        IntStream.range(0, 8).forEach(i -> {
            assertThat(
                    set.add(JinahyaBouncyCastleProviderUtils.newBouncyCastleProvider())
            ).isFalse();
        });
    }

    @Test
    void addBouncyCastleProvider__() {
        assertThatCode(() -> {
            final var result = JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
            log.debug("result: {}", result);
            assertThat(result).isNotEqualTo(-1);
            assertThat(JinahyaBouncyCastleProviderUtils.getInstalledBouncyCastleProvider()).isNotNull();
        }).doesNotThrowAnyException();
        assertThatCode(() -> {
            final var result = JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
            assertThat(result).isEqualTo(-1);
            assertThat(JinahyaBouncyCastleProviderUtils.getInstalledBouncyCastleProvider()).isNotNull();
        }).doesNotThrowAnyException();
        assertThatCode(() -> {
            final var result = JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
            assertThat(result).isEqualTo(-1);
            assertThat(JinahyaBouncyCastleProviderUtils.getInstalledBouncyCastleProvider()).isNotNull();
        }).doesNotThrowAnyException();
    }
}