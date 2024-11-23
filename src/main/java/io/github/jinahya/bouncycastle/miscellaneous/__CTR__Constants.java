package io.github.jinahya.bouncycastle.miscellaneous;

/**
 * Constants for the {@value __CTR__Constants#MODE} mode.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)">Counter
 * (CTR)</a>(Wikipedia)
 */
@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
public final class __CTR__Constants {

    /**
     * The mode of {@value}.
     */
    public static final String MODE = "CTR";

    // -----------------------------------------------------------------------------------------------------------------
    private __CTR__Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
