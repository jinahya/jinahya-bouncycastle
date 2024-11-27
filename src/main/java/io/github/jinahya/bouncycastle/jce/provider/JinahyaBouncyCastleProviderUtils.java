package io.github.jinahya.bouncycastle.jce.provider;

import java.security.Provider;
import java.security.Security;

/**
 * Utilities related to the {@link org.bouncycastle.jce.provider.BouncyCastleProvider} class.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaBouncyCastleProviderConstants
 */
public final class JinahyaBouncyCastleProviderUtils {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Returns a new provider instance for {@value JinahyaBouncyCastleProviderConstants#BOUNCY_CASTLE_PROVIDER_NAME}.
     *
     * @return a new provider instance for {@value JinahyaBouncyCastleProviderConstants#BOUNCY_CASTLE_PROVIDER_NAME}
     */
    public static Provider newBouncyCastleProvider() {
        try {
            return JinahyaBouncyCastleProviderConstants.BOUNCY_CASTLE_PROVIDER_CLASS.getConstructor().newInstance();
        } catch (final ReflectiveOperationException roe) {
            throw new ExceptionInInitializerError(
                    "failed to instantiate " + JinahyaBouncyCastleProviderConstants.BOUNCY_CASTLE_PROVIDER_CLASS
                            + "; " + roe.getMessage()
            );
        }
    }

    // -------------------------------------------------------------------------------------------------------- instance
    private static final Provider BOUNCY_CASTLE_PROVIDER_INSTANCE = newBouncyCastleProvider();

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Adds the {@value JinahyaBouncyCastleProviderConstants#BOUNCY_CASTLE_PROVIDER_NAME} provider to the
     * {@link Security}.
     *
     * @return the result of the {@link Security#addProvider(Provider)} method.
     * @see Security#addProvider(Provider)
     */
    // https://stackoverflow.com/a/45198599/330457
    // https://bugs.openjdk.org/browse/JDK-8168469
    public static synchronized int addBouncyCastleProvider() {
        if (Security.getProvider(JinahyaBouncyCastleProviderConstants.BOUNCY_CASTLE_PROVIDER_NAME) != null) {
            return -1;
        }
        return Security.addProvider(BOUNCY_CASTLE_PROVIDER_INSTANCE);
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Returns the provider <em>installed</em> with
     * {@value JinahyaBouncyCastleProviderConstants#BOUNCY_CASTLE_PROVIDER_NAME}.
     *
     * @return the provider <em>installed</em> for
     * {@value JinahyaBouncyCastleProviderConstants#BOUNCY_CASTLE_PROVIDER_NAME}; {@code null} if no provider with the
     * {@value JinahyaBouncyCastleProviderConstants#BOUNCY_CASTLE_PROVIDER_NAME} is installed.
     * @see Security#getProvider(String)
     * @see JinahyaBouncyCastleProviderConstants#BOUNCY_CASTLE_PROVIDER_NAME
     */
    public static Provider getInstalledBouncyCastleProvider() {
        return Security.getProvider(JinahyaBouncyCastleProviderConstants.BOUNCY_CASTLE_PROVIDER_NAME);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaBouncyCastleProviderUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
