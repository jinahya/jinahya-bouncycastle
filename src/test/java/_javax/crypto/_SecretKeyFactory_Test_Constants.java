package _javax.crypto;

import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
public final class _SecretKeyFactory_Test_Constants {

    public static final List<String> STANDARD_ALGORITHMS = List.of(
            "AES",
            "ARCFOUR",
            "ChaCha20",
            "DES",
            "DESede"
//            "PBEWith<digest>And<encryption>",
//            "PBEWith<prf>And<encryption>",
//            "PBKDF2With<prf>"
    );

    private _SecretKeyFactory_Test_Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
