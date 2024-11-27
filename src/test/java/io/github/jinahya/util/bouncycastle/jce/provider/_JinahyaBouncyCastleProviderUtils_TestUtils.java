package io.github.jinahya.util.bouncycastle.jce.provider;

import _java.security._Provider__Test;
import io.github.jinahya.bouncycastle.jce.provider.JinahyaBouncyCastleProviderConstants;
import io.github.jinahya.bouncycastle.jce.provider.JinahyaBouncyCastleProviderUtils;

import java.security.Provider;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.function.Function;

public final class _JinahyaBouncyCastleProviderUtils_TestUtils {

    public static <R> R applyBouncyCastleProvider(final Function<? super Provider, ? extends R> function) {
        JinahyaBouncyCastleProviderUtils.addBouncyCastleProvider();
        return _Provider__Test.applyProvider(
                JinahyaBouncyCastleProviderConstants.BOUNCY_CASTLE_PROVIDER_NAME,
                function
        );
    }

    public static <R> R callForBouncyCastleProvider(final Callable<? extends R> callable) {
        Objects.requireNonNull(callable, "callable is null");
        return applyBouncyCastleProvider(p -> {
            try {
                return callable.call();
            } catch (final Exception e) {
                throw new RuntimeException("failed to call " + callable, e);
            }
        });
    }

    public static void runForBouncyCastleProvider(final Runnable runnable) {
        Objects.requireNonNull(runnable, "runnable is null");
        callForBouncyCastleProvider(() -> {
            runnable.run();
            return null;
        });
    }

    private _JinahyaBouncyCastleProviderUtils_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
