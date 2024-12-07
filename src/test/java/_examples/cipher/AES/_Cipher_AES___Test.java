package _examples.cipher.AES;

import _examples.cipher._Cipher____Test;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.List;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
abstract class _Cipher_AES___Test
        extends _Cipher____Test {

    static final String ALGORITHM = "AES";

    private static final int BLOCK_SIZE = 128;

    static final int BLOCK_BYTES = BLOCK_SIZE >> 3; // 16

    static final List<Integer> KEY_SIZES = List.of(128, 192, 256);
}
