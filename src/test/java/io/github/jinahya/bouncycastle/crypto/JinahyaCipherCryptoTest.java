package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Objects;

public abstract class JinahyaCipherCryptoTest<CRYPTO extends JinahyaCipherCrypto<CIPHER>, CIPHER>
        extends JinahyaCryptoTest<CRYPTO> {

    protected JinahyaCipherCryptoTest(final Class<CRYPTO> cryptoClass, final Class<CIPHER> cipherClass) {
        super(cryptoClass);
        this.cipherClass = Objects.requireNonNull(cipherClass, "cipherClass is null");
    }

    protected CRYPTO newCryptoInstance(final CIPHER cipher, final CipherParameters params) {
        try {
            final var constructor = cryptoClass.getConstructor(cipherClass, CipherParameters.class);
            return constructor.newInstance(cipher, params);
        } catch (final ReflectiveOperationException roe) {
            throw new RuntimeException(
                    "failed to instantiate " + cryptoClass + " with " + cipher + " and " + params,
                    roe
            );
        }
    }

    protected final Class<CIPHER> cipherClass;
}