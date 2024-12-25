package _java.security;

import lombok.extern.slf4j.Slf4j;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.Stream;

@Slf4j
public final class _Provider__Test_Utils {

    private static Stream<Provider.Service> getServiceStream() {
        return Arrays.stream(Security.getProviders())
                .flatMap(p -> p.getServices().stream())
                ;
    }

    public static Stream<Provider.Service> getServiceStream(final Provider provider) {
        return provider.getServices().stream();
    }

    public static Stream<Provider.Service> getServiceStream(final Provider provider, final String type) {
        return getServiceStream(provider).filter(s -> s.getType().equalsIgnoreCase(type));
    }

    public static Stream<Provider.Service> getServiceStream(final String type) {
        return getServiceStream().filter(s -> s.getType().equalsIgnoreCase(type));
    }

    private _Provider__Test_Utils() {
        throw new IllegalArgumentException("");
    }
}
