package io.github.jinahya.bouncycastle.crypto;

import io.github.jinahya.bouncycastle.miscellaneous._AES___Utils;
import io.github.jinahya.bouncycastle.miscellaneous.__OFB__TestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

class JinahyaStreamCipherUtils_AES_OFB__Test {

    private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return __OFB__TestUtils.getCipherAndParamsArgumentsStream(
                _AES___Utils::getAllowedKeySizeStream,
                AESEngine::newInstance
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
    void processAllByts__(final StreamCipher cipher, final CipherParameters params) throws IOException {
        JinahyaStreamCipherUtils_TestUtils.processAllBytes__(
                cipher,
                params
        );
    }

}