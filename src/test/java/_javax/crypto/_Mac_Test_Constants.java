package _javax.crypto;

import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
public final class _Mac_Test_Constants {

    public static final List<String> STANDARD_ALGORITHMS = List.of(
            "HmacMD5",
            "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512", "HmacSHA512/224", "HmacSHA512/256",
            "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512",
            // ---------------------------------------------------------------------------------------------------------
//            "PBEWith<mac>", // https://tools.ietf.org/html/rfc8018
            "PBEWithSHA1",
            "PBEWithSHA224",
            "PBEWithSHA256",
            "PBEWithSHA384",
            "PBEWithSHA512",
            "PBEWithSHA512/224",
            "PBEWithSHA512/256",
            // ---------------------------------------------------------------------------------------------------------
            "HmacPBESHA1", "HmacPBESHA224", "HmacPBESHA256", "HmacPBESHA384", "HmacPBESHA512", "HmacPBESHA512/224",
            "HmacPBESHA512/256"
    );

    private _Mac_Test_Constants() {
        throw new AssertionError("instantiation is not allowed");
    }
}
