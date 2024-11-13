package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;

class JinahyaAsymmetricBlockCipherCryptoTest<CRYPTO extends JinahyaAsymmetricBlockCipherCrypto>
        extends JinahyaCipherCryptoTest<CRYPTO, AsymmetricBlockCipher> {

    protected JinahyaAsymmetricBlockCipherCryptoTest(final Class<CRYPTO> cryptoClass) {
        super(cryptoClass, AsymmetricBlockCipher.class);
    }
}