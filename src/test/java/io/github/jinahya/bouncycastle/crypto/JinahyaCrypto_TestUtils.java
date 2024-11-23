package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;

import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

public final class JinahyaCrypto_TestUtils {

    static void __array(final JinahyaCrypto crypto) {
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = crypto.encrypt(plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = crypto.decrypt(encrypted);
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).isEqualTo(plain);
    }

    private JinahyaCrypto_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}