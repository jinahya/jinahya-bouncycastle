package io.github.jinahya.bouncycastle.miscellaneous;

/**
 * Constants for the {@link __CBC__Constants#MODE} mode.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __CBC__Constants {

    /**
     * The mode of {@value}.
     */
    public static final String MODE = "CBC";

    // -----------------------------------------------------------------------------------------------------------------
    private __CBC__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
