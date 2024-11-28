package io.github.jinahya.bouncycastle.crypto;

import io.github.jinahya.bouncycastle.miscellaneous._LEA___TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

class JinahyaBlockCipherUtils_LEA_Test {

    static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return _LEA___TestUtils.getCipherAndParamsArgumentsStream();
    }

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("processBlock(cipher, in, inoff, out, outoff)")
    @MethodSource("getCipherAndParamsArgumentsStream")
    @ParameterizedTest
    void processBlock__(final BlockCipher cipher, final CipherParameters params) {
        JinahyaBlockCipherUtils_TestUtils.processBlock__(cipher, params);
    }

    @DisplayName("processAllBlocks(cipher, in, out, inbuf, outbuf, inconsumer, outconsumer)")
    @MethodSource("getCipherAndParamsArgumentsStream")
    @ParameterizedTest
    void processAllBlocks__(final BlockCipher cipher, final CipherParameters params) throws IOException {
        JinahyaBlockCipherUtils_TestUtils.processAllBlocks__(cipher, params);
    }
}