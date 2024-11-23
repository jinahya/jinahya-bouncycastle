package io.github.jinahya.bouncycastle.crypto;

import io.github.jinahya.bouncycastle.miscellaneous._AES___Utils;
import io.github.jinahya.bouncycastle.miscellaneous.__CFB__TestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.MultiBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

class JinahyaMultiBlockCipherUtils_AES_CFB__Test {

    static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return __CFB__TestUtils.getCipherAndParamsArgumentsStream(
                _AES___Utils::getAllowedKeySizeStream,
                AESEngine::newInstance
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("processBlock(cipher, in, inoff, out, outoff)")
    @MethodSource("getCipherAndParamsArgumentsStream")
    @ParameterizedTest
    void processBlock__(final MultiBlockCipher cipher, final CipherParameters params) {
        JinahyaMultiBlockCipherUtils_TestUtils.processBlock__(cipher, params);
    }

    @DisplayName("processAllBlocks(cipher, in, out, inbuf, outbuf, inconsumer, outconsumer)")
    @MethodSource("getCipherAndParamsArgumentsStream")
    @ParameterizedTest
    void processAllBlocks__(final MultiBlockCipher cipher, final CipherParameters params) throws IOException {
        JinahyaMultiBlockCipherUtils_TestUtils.processAllBlocks__(cipher, params);
    }
}