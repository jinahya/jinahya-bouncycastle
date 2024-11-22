package io.github.jinahya.bouncycastle.crypto;

import io.github.jinahya.bouncycastle.miscellaneous._ARIA___Utils;
import io.github.jinahya.bouncycastle.miscellaneous.__CFB__TestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

class JinahyaStreamCipherUtils_ARIA_CFB__Test {

    private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return __CFB__TestUtils.getCipherAndParamsArgumentsStream(
                _ARIA___Utils::getAllowedKeySizeStream,
                ARIAEngine::new
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("processBytes(cipher, in, inoff, inlen, out, outoff)")
    @MethodSource({"getCipherAndParamsArgumentsStream"})
    @ParameterizedTest
    void processBytes__(final StreamCipher cipher, final CipherParameters params) {
        JinahyaStreamCipherUtils_TestUtils.processBytes__(
                cipher,
                params
        );
    }

    @DisplayName("processAllBytes(cipher, in, out, inbuf, outbuf, inconsumer, outconsumer")
    @MethodSource("getCipherAndParamsArgumentsStream")
    @ParameterizedTest
    void processAllBytes__(final StreamCipher cipher, final CipherParameters params) throws IOException {
        JinahyaStreamCipherUtils_TestUtils.processAllBytes__(
                cipher,
                params
        );
    }

}