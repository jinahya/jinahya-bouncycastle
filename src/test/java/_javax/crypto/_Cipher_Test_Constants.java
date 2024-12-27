package _javax.crypto;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public final class _Cipher_Test_Constants {

    public static final Map<String, List<Integer>> TRANSFORMATIONS_REQUIRED_TO_BE_SUPPORTED;

    static {
        final var map = new HashMap<String, List<Integer>>() {
            {
                put("AES/CBC/NoPadding", List.of(128));
                put("AES/CBC/PKCS5Padding", List.of(128));
                put("AES/ECB/NoPadding", List.of(128));
                put("AES/ECB/PKCS5Padding", List.of(128));
                put("AES/GCM/NoPadding", List.of(128));
                put("DESede/CBC/NoPadding", List.of(168));
                put("DESede/CBC/PKCS5Padding", List.of(168));
                put("DESede/ECB/NoPadding", List.of(168));
                put("DESede/ECB/PKCS5Padding", List.of(168));
                put("RSA/ECB/PKCS1Padding", List.of(1024, 2048));
                put("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", List.of(1024, 2048));
                put("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", List.of(1024, 2048));
            }
        };
        TRANSFORMATIONS_REQUIRED_TO_BE_SUPPORTED = Collections.unmodifiableMap(map);
    }

    public static final List<String> STANDARD_ALGORITHMS = List.of(
            "AES",
            "AESWrap",
            "AESWrapPad",
            "ARCFOUR",
            "Blowfish",
            "ChaCha20",
            "ChaCha20-Poly1305",
            "DES",
            "DESede",
            "DESedeWrap",
            "ECIES",
//            "PBEWith<digest>And<encryption>",
//            "PBEWith<prf>And<encryption>",
            "PBEWithMD5AndDES",
            "PBEWithHmacSHA256AndAES_128",
            "RC2",
            "RC4",
            "RC5",
            "RSA"
    );

    static final String SERVICE_TYPE = "Cipher";

    static {
        assert SERVICE_TYPE.equals(Cipher.class.getSimpleName());
    }

    private _Cipher_Test_Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
