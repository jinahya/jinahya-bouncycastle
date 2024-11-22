package io.github.jinahya.bouncycastle.crypto;

import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import _org.junit.jupiter.params.provider._Arguments_TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

class JinahyaBufferedBlockCipherUtils_Padded_Test {

    private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return Stream.concat(
                JinahyaBlockCipherUtils_AES_Test.getCipherAndParamsArgumentsStream(),
                JinahyaBlockCipherUtils_ARIA_Test.getCipherAndParamsArgumentsStream()
        ).map(a -> _Arguments_TestUtils.ofPayloadsMapped(
                a,
                i -> p -> switch (i) {
                    case 0 -> _BufferedBlockCipher_TestUtils.named(new PaddedBufferedBlockCipher((BlockCipher) p));
                    case 1 -> _KeyParameters_TestUtils.named((KeyParameter) p);
                    default -> p;
                }
        ));
    }

    @DisplayName("processBytesAndDoFinal(cipher, in, inoff, inlen, out, outoff)")
    @MethodSource({"getCipherAndParamsArgumentsStream"})
    @ParameterizedTest
    void processBytesAndDoFinal__(final BufferedBlockCipher cipher, final CipherParameters params)
            throws InvalidCipherTextException {
        JinahyaBufferedBlockCipherUtils_TestUtils.processBytesAndDoFinal__(
                cipher,
                params
        );
    }

    @DisplayName("processAllBytesAndDoFinal(cipher, in, out, inbuf, outbuf, inconsumer, outconsumer")
    @MethodSource("getCipherAndParamsArgumentsStream")
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params)
            throws IOException, InvalidCipherTextException {
        JinahyaBufferedBlockCipherUtils_TestUtils.processAllBytesAndDoFinal__(
                cipher,
                params
        );
    }
}