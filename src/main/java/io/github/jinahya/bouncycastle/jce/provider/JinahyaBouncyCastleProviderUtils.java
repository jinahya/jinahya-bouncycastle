package io.github.jinahya.bouncycastle.jce.provider;

import java.security.Provider;
import java.security.Security;

/**
 * Utilities related to the {@link org.bouncycastle.jce.provider.BouncyCastleProvider} class.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
public final class JinahyaBouncyCastleProviderUtils {

    // ----------------------------------------------------------------------------------------------------------- class
    private static final String BOUNCY_CASTLE_PROVIDER_CLASS_NAME =
            "org.bouncycastle.jce.provider.BouncyCastleProvider";

    private static final Class<? extends Provider> BOUNCY_CASTLE_PROVIDER_CLASS;

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

    // -------------------------------------------------------------------------------------------------------- instance
    private static final Provider BOUNCY_CASTLE_PROVIDER_INSTANCE;

    static {
        try {
            BOUNCY_CASTLE_PROVIDER_INSTANCE = BOUNCY_CASTLE_PROVIDER_CLASS.getConstructor().newInstance();
        } catch (final ReflectiveOperationException roe) {
            throw new ExceptionInInitializerError(
                    "failed to instantiate " + BOUNCY_CASTLE_PROVIDER_CLASS + "; " + roe.getMessage()
            );
        }
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Adds the {@value #BOUNCY_CASTLE_PROVIDER_NAME} provider to the {@link Security}.
     *
     * @return the result of the {@link Security#addProvider(Provider)} method.
     * @see Security#addProvider(Provider)
     */
    // https://stackoverflow.com/a/45198599/330457
    // https://bugs.openjdk.org/browse/JDK-8168469
    public static synchronized int addBouncyCastleProvider() {
        if (Security.getProvider(BOUNCY_CASTLE_PROVIDER_NAME) != null) {
            return -1;
        }
        return Security.addProvider(BOUNCY_CASTLE_PROVIDER_INSTANCE);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBouncyCastleProviderUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
