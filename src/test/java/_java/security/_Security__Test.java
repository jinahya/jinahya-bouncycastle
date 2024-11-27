package _java.security;

import org.junit.jupiter.api.Test;

import java.security.Security;

class _Security__Test {

    @Test
    void __() {
        for (final var provider : Security.getProviders()) {
            _Provider__Test.logProvider(provider);
        }
    }
}
