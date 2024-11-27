package _java.security;

import lombok.extern.slf4j.Slf4j;

import java.security.Provider;
import java.security.Security;
import java.util.Objects;
import java.util.function.Function;

@Slf4j
public class _Provider__Test {

    static void logService(final Provider.Service service) {
        log.debug("----------------------------------------");
        log.debug("\tservice: {}", service);
        log.debug("\t\tprovider: {}", service.getProvider());
        log.debug("\t\ttype: {}", service.getType());
        log.debug("\t\tclassName: {}", service.getClassName());
        log.debug("\t\talgorithm: {}", service.getAlgorithm());
    }

    public static void logProvider(final Provider provider) {
        log.debug("provider: {}", provider);
        log.debug("\tname: {}", provider.getName());
        log.debug("\tversionStr: {}", provider.getVersionStr());
        log.debug("\tconfigured: {}", provider.isConfigured());
        log.debug("\tinfo: {}", provider.getInfo());
        provider.getServices().forEach(_Provider__Test::logService);
    }

    public static <R> R applyProvider(final String name, final Function<? super Provider, ? extends R> function) {
        Objects.requireNonNull(name, "name is null");
        Objects.requireNonNull(function, "function is null");
        return function.apply(
                Objects.requireNonNull(Security.getProvider(name), "no provider installed for '" + name + "'")
        );
    }
}
