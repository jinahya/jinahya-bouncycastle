package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.macs._GMac_TestUtils;
import _org.bouncycastle.crypto.macs._HMac_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.crypto.Mac;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
class JinahyaMacUtils_Test {

    private static Stream<Mac> getRandomMacStream() {
        return Stream.of(
                _HMac_TestUtils.newRandomInstance(),
                _GMac_TestUtils.newRandomInstance()
        );
    }

    @DisplayName("update(mac, in, inoff, inlen)")
    @Nested
    class UpdateTest {

        private static Stream<Mac> getRandomMac() {
            return JinahyaMacUtils_Test.getRandomMacStream();
        }

        @MethodSource({"getRandomMac"})
        @ParameterizedTest
        void __(final Mac mac) {
            // --------------------------------------------------------------------------------------------------- given
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            // ---------------------------------------------------------------------------------------------------- when
            final var result = JinahyaMacUtils.update(mac, plain, 0, plain.length);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(result).isSameAs(mac);
        }
    }

    @DisplayName("update(mac, in, inoff, inlen, out, outoff)")
    @Nested
    class UpdateAndDoFinalTest {

        private static Stream<Mac> getRandomMac() {
            return JinahyaMacUtils_Test.getRandomMacStream();
        }

        @MethodSource({"getRandomMac"})
        @ParameterizedTest
        void __(final Mac mac) {
            // --------------------------------------------------------------------------------------------------- given
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            final var out = new byte[mac.getMacSize()];
            // ---------------------------------------------------------------------------------------------------- when
            final var bytes = JinahyaMacUtils.updateAndDoFinal(mac, plain, 0, plain.length, out, 0);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(bytes).isSameAs(out.length);
        }
    }

    @DisplayName("updateAll(mac, in, inoff, inlen)")
    @Nested
    class UpdateAllTest {

        private static Stream<Mac> getRandomMac() {
            return JinahyaMacUtils_Test.getRandomMacStream();
        }

        @MethodSource({"getRandomMac"})
        @ParameterizedTest
        void __(final Mac mac) throws IOException {
            // --------------------------------------------------------------------------------------------------- given
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            // ---------------------------------------------------------------------------------------------------- when
            final var result = JinahyaMacUtils.updateAll(
                    mac,
                    new ByteArrayInputStream(plain),
                    new byte[ThreadLocalRandom.current().nextInt(128) + 1]
            );
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(result).isSameAs(mac);
        }
    }

    @DisplayName("updateAll(mac, in, inoff, inlen, out, outoff)")
    @Nested
    class UpdateAllAndDoFinalTest {

        private static Stream<Mac> getRandomMac() {
            return JinahyaMacUtils_Test.getRandomMacStream();
        }

        @MethodSource({"getRandomMac"})
        @ParameterizedTest
        void __(final Mac mac) throws IOException {
            // --------------------------------------------------------------------------------------------------- given
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            final var out = new byte[mac.getMacSize()];
            // ---------------------------------------------------------------------------------------------------- when
            final var bytes = JinahyaMacUtils.updateAllAndDoFinal(
                    mac,
                    new ByteArrayInputStream(plain),
                    new byte[ThreadLocalRandom.current().nextInt(128) + 1],
                    out,
                    0
            );
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(bytes).isSameAs(out.length);
        }
    }
}