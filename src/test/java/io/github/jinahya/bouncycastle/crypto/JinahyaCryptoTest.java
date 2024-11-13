package io.github.jinahya.bouncycastle.crypto;

import java.util.Objects;

public abstract class JinahyaCryptoTest<CRYPTO extends JinahyaCrypto> {

    protected JinahyaCryptoTest(final Class<CRYPTO> cryptoClass) {
        super();
        this.cryptoClass = Objects.requireNonNull(cryptoClass, "cryptoClass is null");
    }

    protected final Class<CRYPTO> cryptoClass;
}