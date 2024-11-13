package io.github.jinahya.bouncycastle.crypto;

import java.util.Objects;

public abstract class JinahyaCipherCryptoTest<CRYPTO extends JinahyaCipherCrypto<CIPHER>, CIPHER>
        extends JinahyaCryptoTest<CRYPTO> {

    protected JinahyaCipherCryptoTest(final Class<CRYPTO> cryptoClass, final Class<CIPHER> cipherClass) {
        super(cryptoClass);
        this.cipherClass = Objects.requireNonNull(cipherClass, "cipherClass is null");
    }

    protected final Class<CIPHER> cipherClass;
}