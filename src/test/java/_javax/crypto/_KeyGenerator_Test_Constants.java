package _javax.crypto;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyGenerator;
import java.util.List;

@Slf4j
public final class _KeyGenerator_Test_Constants {

    public static final List<String> ALGORITHMS_REQUIRED_TO_SUPPORT = List.of(
            "AES",
            "DESede",
            "HmacSHA1",
            "HmacSHA256"
    );

    static {
        assert ALGORITHMS_REQUIRED_TO_SUPPORT.containsAll(_Mac_Test_Constants.ALGORITHMS_REQUIRED_TO_SUPPORT);
    }

    public static final List<String> STANDARD_ALGORITHMS = List.of(
            "AES",
            "ARCFOUR",
            "Blowfish",
            "ChaCha20",
            "DES",
            "DESede",
            "HmacMD5",
            "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512", "HmacSHA512/224", "HmacSHA512/256",
            "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512",
            "RC2"
    );

    static final String SERVICE_TYPE = "KeyGenerator";

    static {
        assert SERVICE_TYPE.equals(KeyGenerator.class.getSimpleName());
    }

    private _KeyGenerator_Test_Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
