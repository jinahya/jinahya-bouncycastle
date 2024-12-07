package _examples.message_digest;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

@DisplayName(MessageDigest_SHA_3_224_Test.ALGORITHM)
@Slf4j
class MessageDigest_SHA_3_224_Test
        extends MessageDigest____Test {

    static final String ALGORITHM = "SHA3-224";

    @TestFactory
    Stream<DynamicTest> __empty() {
        final var input = new byte[0];
        log.debug(" input: ({}) {}", formatLength(input.length),
                  HexFormat.of().withUpperCase().formatHex(input));
        return MessageDigest_TestUtils.getDynamicTestStream(ALGORITHM, input);
    }

    @TestFactory
    Stream<DynamicTest> __() {
        final var input = new byte[ThreadLocalRandom.current().nextInt(32) + 1];
        ThreadLocalRandom.current().nextBytes(input);
        log.debug(" input: ({}) {}", formatLength(input.length),
                  HexFormat.of().withUpperCase().formatHex(input));
        return MessageDigest_TestUtils.getDynamicTestStream(ALGORITHM, input);
    }

    @TestFactory
    Stream<DynamicTest> __(@TempDir final File tempDir) throws IOException {
        return MessageDigest_TestUtils.getDynamicTestStream(ALGORITHM, tempDir);
    }
}
