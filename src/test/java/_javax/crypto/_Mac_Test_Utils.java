package _javax.crypto;

import _java.security._Provider__Test_Utils;
import _java.security._Security__Test_Utils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.params.aggregator.ArgumentsAggregationException;
import org.junit.jupiter.params.aggregator.ArgumentsAggregator;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Mac;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.stream.Stream;

@Slf4j
public final class _Mac_Test_Utils {

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<String> getStandardAlgorithmStream() {
        return _Mac_Test_Constants.STANDARD_ALGORITHMS.stream();
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._Mac_Test_Utils#getStandardAlgorithmStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardMacAlgorithms {

    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<Provider.Service> getServiceStream() {
        return _Provider__Test_Utils.getServiceStream(Mac.class.getSimpleName());
    }

    public static Stream<Provider> getProviderStream() {
        return _Security__Test_Utils.getProviderStream(Mac.class.getSimpleName());
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._Mac_Test_Utils#getProviderStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithProviders {

    }

    public static Stream<String> getProviderNameStream() {
        return getProviderStream()
                .map(Provider::getName);
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._Mac_Test_Utils#getProviderNameStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithProviderNames {

    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<Arguments> getStandardAlgorithmAndProviderArgumentsStream() {
        return getStandardAlgorithmStream()
                .flatMap(a -> getProviderStream().map(p -> Arguments.of(a, p)));
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._Mac_Test_Utils#getStandardAlgorithmAndProviderArgumentsStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardAlgorithmsAndProviders {

    }

    public static Stream<Arguments> getStandardAlgorithmAndProviderNameArgumentsStream() {
        return getStandardAlgorithmStream()
                .flatMap(a -> getProviderNameStream().map(p -> Arguments.of(a, p)));
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_java.crypto._Mac_Test_Utils#getStandardAlgorithmAndProviderNameArgumentsStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardAlgorithmsAndProviderNames {

    }

    // -----------------------------------------------------------------------------------------------------------------
    static class MacArgumentsAggregator
            implements ArgumentsAggregator {

        @Override
        public Mac aggregateArguments(final ArgumentsAccessor accessor, final ParameterContext context)
                throws ArgumentsAggregationException {
            final var algorithm = accessor.getString(0);
            final var provider = accessor.get(1, Provider.class);
            try {
                return Mac.getInstance(algorithm, provider);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new ArgumentsAggregationException(
                        "failed to get instance with " + algorithm + " and " + provider,
                        nsae
                );
            }
        }
    }

    @MethodSource("_java.crypto._Mac_Test_Utils#getStandardAlgorithmAndProviderArgumentsStream()")
    @ParameterizedTest
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    public @interface ParameterizedTestWithMac {

    }

    // -----------------------------------------------------------------------------------------------------------------
    private _Mac_Test_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
