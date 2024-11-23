package io.github.jinahya.bouncycastle.crypto;

import io.github.jinahya.bouncycastle.miscellaneous._AES___Utils;
import io.github.jinahya.bouncycastle.miscellaneous.__CBC_PKCS7Padding_TestUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

class JinahyaBufferedBlockCipherUtils_AES_CBC_PKCS7Padding_Test {

    static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return __CBC_PKCS7Padding_TestUtils.getCipherAndParamsArgumentsStream(
                _AES___Utils::getAllowedKeySizeStream,
                AESEngine::newInstance
        );
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
    void processAllBytesAndDoFinal__(final BufferedBlockCipher cipher, final CipherParameters params)
            throws IOException, InvalidCipherTextException {
        JinahyaBufferedBlockCipherUtils_TestUtils.processAllBytesAndDoFinal__(
                cipher,
                params
        );
    }
}