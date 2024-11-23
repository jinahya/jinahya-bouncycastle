package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Objects;

/**
 * An abstract crypto class for a specific type of cipher.
 *
 * @param <CIPHER> cipher type parameter
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S119" // Type parameter names should comply with a naming convention
})
public abstract class JinahyaCipherCrypto<CIPHER>
        implements JinahyaCrypto {

    /**
     * Creates a new instance with specified cipher and initialization parameters.
     *
     * @param cipher the cipher.
     * @param params the initialization parameters for the {@code cipher}.
     * @see #cipher
     * @see #params
     */
    protected JinahyaCipherCrypto(final CIPHER cipher, final CipherParameters params) {
        super();
        this.cipher = Objects.requireNonNull(cipher, "cipher is null");
        this.params = Objects.requireNonNull(params, "params is null");
    }

    // ---------------------------------------------------------------------------------------------------------- cipher

    /**
     * Initialize the {@link #cipher} for specified boolean flag of encryption.
     *
     * @param encryption {@code true} for encryption; {@code false} for decryption.
     */
    protected abstract void initFor(final boolean encryption);

    /**
     * Initialize the {@link #cipher} for encryption.
     */
    protected void initForEncryption() {
        initFor(true);
    }

    /**
     * Initialize the {@link #cipher} for decryption.
     */
    protected void initForDecryption() {
        initFor(false);
    }

    // ---------------------------------------------------------------------------------------------------------- cipher

    // ---------------------------------------------------------------------------------------------------------- params

    /**
     * Returns the value of {@code params} property.
     *
     * @return the value of {@code params} property
     */
    public CipherParameters getParams() {
        return params;
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * a cipher to use.
     */
    protected final CIPHER cipher;

    /**
     * a cipher parameters for initializing {@link #cipher}.
     */
    protected final CipherParameters params;
}
