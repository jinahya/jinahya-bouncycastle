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
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.Stream;

@Slf4j
public final class _MessageDigest_Test_Utils {

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<String> getStandardAlgorithmStream() {
        return _MessageDigest_Test_Constants.STANDARD_ALGORITHMS.stream();
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_java.security._MessageDigest_Test_Utils#getStandardAlgorithmStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardMessageDigestAlgorithms {

    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<Provider> getProviderStream() {
        return Arrays.stream(Security.getProviders())
                .flatMap(p -> p.getServices().stream())
                .filter(s -> MessageDigest.class.getSimpleName().equalsIgnoreCase(s.getType()))
                .map(Provider.Service::getProvider)
                .distinct();
    }

    public static Stream<String> getProviderNameStream() {
        return getProviderStream()
                .map(Provider::getName);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static Stream<Arguments> getStandardAlgorithmAndProviderNameArgumentsStream() {
        return getStandardAlgorithmStream()
                .flatMap(a -> getProviderNameStream().map(p -> Arguments.of(a, p)));
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_java.security._MessageDigest_Test_Utils#getStandardAlgorithmAndProviderNameArgumentsStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithStandardMessageDigestAlgorithmsAndProviderNames {

    }

    // -----------------------------------------------------------------------------------------------------------------
    static class MessageDigestAggregator
            implements ArgumentsAggregator {

        @Override
        public MessageDigest aggregateArguments(final ArgumentsAccessor accessor, final ParameterContext context)
                throws ArgumentsAggregationException {
            final var algorithm = accessor.getString(0);
            final var provider = accessor.getString(1);
            try {
                return MessageDigest.getInstance(algorithm, provider);
            } catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
                throw new ArgumentsAggregationException(
                        "failed to get instance with " + algorithm + ", " + provider,
                        e
                );
            }
        }
    }

    @MethodSource("_java.security._MessageDigest_Test_Utils#getStandardAlgorithmAndProviderNameArgumentsStream()")
    @ParameterizedTest
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    public @interface ParameterizedTestWithMessageDigest {

    }

    // -----------------------------------------------------------------------------------------------------------------
    private _MessageDigest_Test_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
