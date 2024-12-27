package _javax.crypto;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.Stream;

@Slf4j
public final class _KeyGenerator_Test_Utils {

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * Returns a stream of {@link java.security.Provider.Service}s whose {@link Provider.Service#getType() type} equals
     * to {@value _KeyGenerator_Test_Constants#SERVICE_TYPE}.
     *
     * @return a stream of {@link java.security.Provider.Service}s
     */
    static Stream<Provider.Service> getServiceStream() {
        return Arrays.stream(Security.getProviders())
                .flatMap(p -> p.getServices().stream())
                .filter(s -> _KeyGenerator_Test_Constants.SERVICE_TYPE.equalsIgnoreCase(s.getType()));
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._KeyGenerator_Test_Utils#getServiceStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithService {

    }

    static Stream<Provider> getProviderStream() {
        return getServiceStream()
                .map(Provider.Service::getProvider)
                .distinct();
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._KeyGenerator_Test_Utils#getProviderStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithProviders {

    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<String> getStandardAlgorithmStream() {
        return _KeyGenerator_Test_Constants.STANDARD_ALGORITHMS.stream();
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._KeyGenerator_Test_Utils#getStandardAlgorithmStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardAlgorithms {

    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<Arguments> getStandardAlgorithmAndProviderArgumentsStream() {
        return getStandardAlgorithmStream().flatMap(a -> getProviderStream().map(p -> Arguments.of(a, p)));
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._KeyGenerator_Test_Utils#getStandardAlgorithmAndProviderArgumentsStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardAlgorithmsAndProviders {

    }

    // -----------------------------------------------------------------------------------------------------------------
    private _KeyGenerator_Test_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
