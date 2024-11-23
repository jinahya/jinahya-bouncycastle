package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.util.stream.Stream;

class JinahyaBufferedBlockCipherCrypto_Padded_Test
        extends JinahyaCipherCryptoTest<JinahyaBufferedBlockCipherCrypto, BufferedBlockCipher> {

    static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return JinahyaBufferedBlockCipherUtils_Padded_Test.getCipherAndParamsArgumentsStream();
    }

    JinahyaBufferedBlockCipherCrypto_Padded_Test() {
        super(JinahyaBufferedBlockCipherCrypto.class, BufferedBlockCipher.class);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @DisplayName("decrypt(encrypt(array))")
    @MethodSource({"getCipherAndParamsArgumentsStream"})
    @ParameterizedTest
    void __array(final BufferedBlockCipher cipher, final CipherParameters params) {
        final var crypto = newCryptoInstance(cipher, params);
        JinahyaCrypto_TestUtils.__array(crypto);
    }

    @DisplayName("decrypt(encrypt(stream))")
    @MethodSource({"getCipherAndParamsArgumentsStream"})
    @ParameterizedTest
    void __stream(final BufferedBlockCipher cipher, final CipherParameters params) throws IOException {
        final var crypto = newCryptoInstance(cipher, params);
        JinahyaCipherCrypto_TestUtils.__stream(crypto);
    }
}