package _java.security;

import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.util.List;

@Slf4j
public final class _MessageDigest_Test_Constants {

    public static final String SERVICE_TYPE = MessageDigest.class.getSimpleName();

    public static final List<String> ALGORITHMS_REQUIRED_TO_BE_SUPPORTED = List.of(
            "SHA-1",
            "SHA-256"
    );

    public static final List<String> STANDARD_ALGORITHMS = List.of(
            "MD2",
            "MD5",
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"
    );

    private _MessageDigest_Test_Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
