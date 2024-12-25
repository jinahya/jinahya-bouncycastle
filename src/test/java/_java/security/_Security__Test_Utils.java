package _java.security;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.Stream;

public class _Security__Test_Utils {

    public static Stream<Provider> getProviderStream() {
        return Arrays.stream(Security.getProviders());
    }

    public static Stream<Provider> getProviderStream(final String type) {
        return _Provider__Test_Utils.getServiceStream(type)
                .map(Provider.Service::getProvider)
                .distinct();
    }

    private _Security__Test_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
