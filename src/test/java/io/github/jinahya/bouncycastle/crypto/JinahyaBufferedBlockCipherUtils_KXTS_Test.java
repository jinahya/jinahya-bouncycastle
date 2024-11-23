package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import _org.junit.jupiter.api._Named_TestUtils;
import _org.junit.jupiter.params.provider._Arguments_TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.KXTSBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

class JinahyaBufferedBlockCipherUtils_KXTS_Test {

    static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return Stream.concat(
                JinahyaBlockCipherUtils_AES_Test.getCipherAndParamsArgumentsStream(),
                JinahyaBlockCipherUtils_ARIA_Test.getCipherAndParamsArgumentsStream()
        ).map(a -> {
            final var got = a.get();
            final var cipher = _Named_TestUtils.<BlockCipher>payload(got[0]);
            final var params = new ParametersWithIV(
                    _Named_TestUtils.payload(got[1]),
                    _Random_TestUtils.newRandomBytes(cipher.getBlockSize())
            );
            return _Arguments_TestUtils.ofPayloadsMapped(
                    a,
                    i -> p -> switch (i) {
                        case 0 -> _BufferedBlockCipher_TestUtils.named(new KXTSBlockCipher(cipher));
                        case 1 -> _ParametersWithIV_TestUtils.named(params);
                        default -> p;
                    }
            );
        });
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