package io.github.jinahya.bouncycastle.crypto.modes;

import io.github.jinahya.bouncycastle.miscellaneous._AES___Utils;
import io.github.jinahya.bouncycastle.miscellaneous.__GCM__TestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

class JinahyaAEADBlockCipherUtils_AES_GCM__Test {

    private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return __GCM__TestUtils.getCipherAndParamsArgumentsStream(
                _AES___Utils::getAllowedKeySizeStream,
                AESEngine::newInstance
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({
            "getCipherAndParamsArgumentsStream"
    })
    @ParameterizedTest
    void processBytesAndDoFinal__(final AEADBlockCipher cipher, final CipherParameters params)
            throws InvalidCipherTextException {
        JinahyaAEADBlockCipherUtils_TestUtils.processBytesAndDoFinal__(cipher, params);
    }

    @MethodSource({
            "getCipherAndParamsArgumentsStream"
    })
    @ParameterizedTest
    void processAllBytesAndDoFinal__(final AEADBlockCipher cipher, final CipherParameters params)
            throws IOException, InvalidCipherTextException {
        JinahyaAEADBlockCipherUtils_TestUtils.processAllBytesAndDoFinal__(cipher, params);
    }
}