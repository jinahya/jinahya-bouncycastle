package _org.bouncycastle.crypto;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class _AsymmetricBlockCipher_TestUtils {

//    public static String cipherName(final AsymmetricBlockCipher cipher) {
//        Objects.requireNonNull(cipher, "cipher is null");
//        return _BlockCipher_TestUtils.cipherName(cipher.getUnderlyingCipher());
//    }

//    public static String cipherName(final AsymmetricBlockCipher cipher, final BlockCipherPadding padding) {
//        return _BlockCipher_TestUtils.cipherName(
//                Objects.requireNonNull(cipher, "cipher is null").getUnderlyingCipher(),
//                padding
//        );
//    }

//    public static void __(final AsymmetricBlockCipher cipher, final CipherParameters params, final byte[] plain) {
//        final var adapter = new JinahyaAsymmetricBlockCipherCrypto(cipher, params);
//        // ----------------------------------------------------------------------------------------------------- encrypt
//        final var encrypted = adapter.encrypt(plain);
//        // ----------------------------------------------------------------------------------------------------- decrypt
//        final var decrypted = adapter.decrypt(encrypted);
//        // -------------------------------------------------------------------------------------------------------- then
//        assertThat(decrypted).isEqualTo(plain);
//    }
//
//    public static void __(final AsymmetricBlockCipher cipher, final CipherParameters params) throws Exception {
//        __(cipher, params, new byte[0]); // empty
//        __(cipher, params, new byte[1]); // single-zero
//        __(cipher, params, _Random_TestUtils.newRandomBytes(1)); // single-random
//        __(cipher, params, _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024)));
//        JinahyaAsymmetricBlockCipherUtilsTest.__(cipher, params);
//        JinahyaBlockCipherUtilsTest.__(cipher.getUnderlyingCipher(), params);
//    }
//
//    public static void __(final AsymmetricBlockCipher cipher, final CipherParameters params, final File dir,
//                          final File plain)
//            throws IOException {
//        final var adapter = new JinahyaAsymmetricBlockCipherCrypto(cipher, params);
//        // ----------------------------------------------------------------------------------------------------- encrypt
//        final var encrypted = File.createTempFile("tmp", null, dir);
//        try (var in = new FileInputStream(plain);
//             var out = new FileOutputStream(encrypted)) {
//            final var bytes = adapter.encrypt(
//                    in,
//                    out,
//                    new byte[ThreadLocalRandom.current().nextInt(cipher.getBlockSize()) + 1]
//            );
//            assert bytes >= 0;
//            out.flush();
//        }
//        // ----------------------------------------------------------------------------------------------------- decrypt
//        final var decrypted = File.createTempFile("tmp", null, dir);
//        try (var in = new FileInputStream(encrypted);
//             var out = new FileOutputStream(decrypted)) {
//            final var bytes = adapter.decrypt(
//                    in,
//                    out,
//                    new byte[ThreadLocalRandom.current().nextInt(cipher.getBlockSize()) + 1]
//            );
//            assert bytes >= 0;
//        }
//        // -------------------------------------------------------------------------------------------------------- then
//        assertThat(decrypted).hasSize(plain.length());
//        assertThat(decrypted).hasSameBinaryContentAs(plain);
//    }
//
//    public static void __(final AsymmetricBlockCipher cipher, final CipherParameters params, final File dir)
//            throws Exception {
//        __(cipher, params, dir, File.createTempFile("tmp", null, dir)); // empty
//        __(cipher, params, dir, _Random_TestUtils.createTempFileWithRandomBytesWritten(dir)); // random
//    }

    // -----------------------------------------------------------------------------------------------------------------
    private _AsymmetricBlockCipher_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
