package _org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.params.AEADParameters;
import org.junit.jupiter.api.Named;

import java.util.Objects;
import java.util.Optional;

public final class _AEADParameters_TestUtils {

    public static String associatedTextString(final byte[] associatedText) {
        final var formatted = Optional.ofNullable(associatedText)
                .filter(v -> v.length > 0)
                .map(v -> String.format("%1$02x", v[0]))
                .orElse("<none/empty>");
        return String.format("associatedText(%1$s)", formatted);
    }

    public static String paramsString(final AEADParameters params) {
        Objects.requireNonNull(params, "params is null");
        return _KeyParameters_TestUtils.paramsString(params.getKey()) +
                " with " +
                associatedTextString(params.getAssociatedText());
    }

    public static <T extends AEADParameters> Named<T> named(final T params) {
        return Named.of(paramsString(params), params);
    }

    private _AEADParameters_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
