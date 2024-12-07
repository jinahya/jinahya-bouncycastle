package _examples.cipher.ARIA;

import _examples.cipher._Cipher____Test;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.junit.jupiter.params.provider.Arguments;

import java.util.List;
import java.util.stream.Stream;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
abstract class _Cipher_ARIA___Test
        extends _Cipher____Test {

    static final String ALGORITHM = "ARIA";

    private static final int BLOCK_SIZE = 128;

    static final int BLOCK_BYTES = BLOCK_SIZE >> 3; // 16

    static final List<Integer> KEY_SIZES = List.of(128, 192, 256);

    static Stream<Arguments> getProviderAndKeySizeArgumentsStream() {
        return PROVIDER_NAME_LIST.stream().flatMap(p -> KEY_SIZES.stream().map(ks -> Arguments.of(p, ks)));
    }
}
