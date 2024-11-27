package io.github.jinahya.bouncycastle.jce.provider;

import java.security.Provider;

/**
 * Constants related to the {@link org.bouncycastle.jce.provider.BouncyCastleProvider} class.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaBouncyCastleProviderUtils
 */
public final class JinahyaBouncyCastleProviderConstants {

    // ----------------------------------------------------------------------------------------------------------- class
    private static final String BOUNCY_CASTLE_PROVIDER_CLASS_NAME =
            "org.bouncycastle.jce.provider.BouncyCastleProvider";

    static final Class<? extends Provider> BOUNCY_CASTLE_PROVIDER_CLASS;

    static {
        try {
            BOUNCY_CASTLE_PROVIDER_CLASS = Class.forName(BOUNCY_CASTLE_PROVIDER_CLASS_NAME).asSubclass(Provider.class);
        } catch (final ReflectiveOperationException roe) {
            throw new ExceptionInInitializerError(
                    "failed to find the class for '" + BOUNCY_CASTLE_PROVIDER_CLASS_NAME + "'; " + roe.getMessage()
            );
        }
    }

    // ------------------------------------------------------------------------------------------------------------ name

    /**
     * The name of the Bouncy Castle provider. The value is {@value}.
     */
    public static final String BOUNCY_CASTLE_PROVIDER_NAME = "BC";

    static {
        final var name = "PROVIDER_NAME";
        try {
            final var field = BOUNCY_CASTLE_PROVIDER_CLASS.getField(name);
            assert field.canAccess(null);
            assert BOUNCY_CASTLE_PROVIDER_NAME.equals(field.get(null));
        } catch (final ReflectiveOperationException roe) {
            throw new ExceptionInInitializerError(
                    "failed to find/get '" + name + "' field from " + BOUNCY_CASTLE_PROVIDER_CLASS
                            + "; " + roe.getMessage());
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBouncyCastleProviderConstants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
