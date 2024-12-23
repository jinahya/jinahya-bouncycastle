package _java.security;

import lombok.extern.slf4j.Slf4j;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

@Slf4j
public final class _Provider__Test_Utils {

    static final List<String> PROVIDER_NAMES = List.of(
            "SUN",
            "BC"
    );

    private static Stream<Provider.Service> getServices() {
        return Arrays.stream(Security.getProviders())
                .flatMap(p -> p.getServices().stream())
                ;
    }

    private _Provider__Test_Utils() {
        throw new IllegalArgumentException("");
    }
}
