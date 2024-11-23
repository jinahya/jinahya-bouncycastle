package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BufferedBlockCipher;

public abstract class JinahyaBufferedBlockCipherCryptoTest<CRYPTO extends JinahyaBufferedBlockCipherCrypto>
        extends JinahyaCipherCryptoTest<CRYPTO, BufferedBlockCipher> {

    protected JinahyaBufferedBlockCipherCryptoTest(final Class<CRYPTO> cryptoClass) {
        super(cryptoClass, BufferedBlockCipher.class);
    }
}