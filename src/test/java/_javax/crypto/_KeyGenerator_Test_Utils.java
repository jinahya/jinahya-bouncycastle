package _javax.crypto;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.KeyGenerator;
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
    static Stream<Provider.Service> getServiceStream() {
        final var type = KeyGenerator.class.getSimpleName();
        return Arrays.stream(Security.getProviders())
                .flatMap(p -> p.getServices().stream())
                .filter(s -> type.equalsIgnoreCase(s.getType()));
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
    public @interface ParameterizedTestWithProvider {

    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<String> getStandardAlgorithmStream() {
        return _KeyGenerator_Test_Constants.STANDARD_ALGORITHMS.stream();
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._KeyGenerator_Test_Utils#getStandardAlgorithmStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardKeyGeneratorAlgorithms {

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
