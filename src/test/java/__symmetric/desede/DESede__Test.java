package __symmetric.desede;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.stream.IntStream;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Slf4j
public abstract class DESede__Test {

    public static final String ALGORITHM = "DESede";

    // -----------------------------------------------------------------------------------------------------------------
    public static final int BLOCK_SIZE = 64;

    public static final int BLOCK_BYTES = BLOCK_SIZE >> 3;

    // -----------------------------------------------------------------------------------------------------------------
    public static IntStream getKeySizeStream() {
        return IntStream.of(
                196
        );
    }

    public static IntStream getKeyBytesStream() {
        return getKeySizeStream().map(ks -> ks >> 3);
    }
}
