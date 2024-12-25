package _java.security;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.params.aggregator.ArgumentsAggregationException;
import org.junit.jupiter.params.aggregator.ArgumentsAggregator;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.stream.Stream;

@Slf4j
public final class _MessageDigest_Test_Utils {

    public static Stream<Provider.Service> getServiceStream() {
        return _Provider__Test_Utils.getServiceStream(_MessageDigest_Test_Constants.SERVICE_TYPE);
    }

    public static Stream<Provider> getProviderStream() {
        return _Security__Test_Utils.getProviderStream(_MessageDigest_Test_Constants.SERVICE_TYPE);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<String> getStandardAlgorithmStream() {
        return _MessageDigest_Test_Constants.STANDARD_ALGORITHMS.stream();
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_java.security._MessageDigest_Test_Utils#getStandardAlgorithmStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardAlgorithms {

    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<Arguments> getStandardAlgorithmAndProviderNameArgumentsStream() {
        return getStandardAlgorithmStream()
                .flatMap(a -> getProviderStream().map(p -> Arguments.of(a, p.getName())));
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_java.security._MessageDigest_Test_Utils#getStandardAlgorithmAndProviderNameArgumentsStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardAlgorithmsAndProviderNames {

    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<Arguments> getStandardAlgorithmAndProviderArgumentsStream() {
        return getStandardAlgorithmStream()
                .flatMap(a -> getProviderStream().map(p -> Arguments.of(a, p)));
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_java.security._MessageDigest_Test_Utils#getStandardAlgorithmAndProviderArgumentsStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardAlgorithmsAndProviders {

    }

    // -----------------------------------------------------------------------------------------------------------------
    static class AlgorithmAndProviderArgumentsAggregator
            implements ArgumentsAggregator {

        @Override
        public MessageDigest aggregateArguments(final ArgumentsAccessor accessor, final ParameterContext context)
                throws ArgumentsAggregationException {
            final var algorithm = accessor.getString(0);
            final var provider = accessor.get(1, Provider.class);
            try {
                return MessageDigest.getInstance(algorithm, provider);
            } catch (final NoSuchAlgorithmException nsae) {
                throw new ArgumentsAggregationException(
                        "failed to get instance with " + algorithm + ", " + provider,
                        nsae
                );
            }
        }
    }

    @MethodSource("_java.security._MessageDigest_Test_Utils#getStandardAlgorithmAndProviderArgumentsStream()")
    @ParameterizedTest
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    public @interface ParameterizedTestWithMessageDigestInstance {

    }

    // -----------------------------------------------------------------------------------------------------------------
    private _MessageDigest_Test_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
