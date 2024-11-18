package _javax.crypto;

import io.github.jinahya.bouncycastle.miscellaneous._RSA_Constants;
import __symmetric._JCEProviderTest;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class _Shall_We_Dance_Test
        extends _JCEProviderTest {

    public static final String PROVIDER = "BC";

    // -----------------------------------------------------------------------------------------------------------------
    public static final String ASYMMETRIC_ALGORITHM = _RSA_Constants.ALGORITHM;

    public static final String ASYMMETRIC_MODE = "ECB";

    public static final String ASYMMETRIC_PADDING = "PKCS1Padding";

    public static final String ASYMMETRIC_TRANSFORMATION =
            ASYMMETRIC_ALGORITHM + '/' + ASYMMETRIC_MODE + '/' + ASYMMETRIC_PADDING;

    public static final int ASYMMETRIC_KEY_SIZE = 1024;

    // -----------------------------------------------------------------------------------------------------------------
    public static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

    // -----------------------------------------------------------------------------------------------------------------
    public static final String SYMMETRIC_ALGORITHM = "AES";

    public static final String SYMMETRIC_MODE = "CBC";

    public static final String SYMMETRIC_PADDING = "PKCS5Padding";

    public static final String SYMMETRIC_TRANSFORMATION =
            SYMMETRIC_ALGORITHM + '/' + SYMMETRIC_MODE + '/' + SYMMETRIC_PADDING;

    public static final int SYMMETRIC_KEY_SIZE = 128;

    public static final int SYMMETRIC_BLOCK_SIZE = 128;

    public static final int SYMMETRIC_BLOCK_BYTES = SYMMETRIC_BLOCK_SIZE >> 3;

    // -----------------------------------------------------------------------------------------------------------------
    private static class Subject {

        Subject() throws Exception {
            final var generator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM, PROVIDER);
            generator.initialize(ASYMMETRIC_KEY_SIZE);
            keyPair = generator.generateKeyPair();
        }

        final KeyPair keyPair;

        SecretKey secretKey;

        IvParameterSpec params;

        byte[] message;
    }

    @Test
    void __() throws Exception {
        final var server = new Subject();
        final var client = new Subject();
        // ---------------------------------------------------------- client sends the client's public key to the server
        // done
        // ----------------------------------------------------- server generates/signs/sends a secret key to the client
        final byte[] encryptedSecretKey;
        final byte[] secretKeySignature;
        {
            final var generator = KeyGenerator.getInstance(SYMMETRIC_ALGORITHM, PROVIDER);
            generator.init(SYMMETRIC_KEY_SIZE);
            server.secretKey = generator.generateKey();
            // ----------------------------------------------------------------------------- encrypt with server.private
            final var cipher = Cipher.getInstance(ASYMMETRIC_TRANSFORMATION, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, server.keyPair.getPrivate());
            encryptedSecretKey = cipher.doFinal(server.secretKey.getEncoded());
            // -------------------------------------------------------------------------------- sign with server.private
            final var signature = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
            signature.initSign(server.keyPair.getPrivate());
            signature.update(server.secretKey.getEncoded());
            secretKeySignature = signature.sign();
        }
        // ------------------------------------------------------------ client receives/decrypts/verifies the secret key
        {
            // ------------------------------------------------------------------------ decrypt with server's public key
            final var cipher = Cipher.getInstance(ASYMMETRIC_TRANSFORMATION, PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, server.keyPair.getPublic());
            cipher.update(encryptedSecretKey);
            final var decryptedSecretKey = cipher.doFinal();
            assertThat(decryptedSecretKey).isEqualTo(server.secretKey.getEncoded());
            client.secretKey = new SecretKeySpec(decryptedSecretKey, SYMMETRIC_ALGORITHM);
            // ------------------------------------------------------------------------- verify with server's public key
            final var signature = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
            signature.initVerify(server.keyPair.getPublic());
            signature.update(decryptedSecretKey);
            final boolean verified = signature.verify(secretKeySignature);
            assertThat(verified).isTrue();
        }
        // --------------------------------------------------------------------------- client encrypts/signs/sends an iv
        {
            final var decryptedIv = new byte[SYMMETRIC_BLOCK_BYTES];
            ThreadLocalRandom.current().nextBytes(decryptedIv);
            client.params = new IvParameterSpec(decryptedIv);
        }
        final byte[] encryptedIv;
        final byte[] ivSignature;
        {
            // ----------------------------------------------------------------------- encrypt with client's private key
            final var cipher = Cipher.getInstance(ASYMMETRIC_TRANSFORMATION, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, client.keyPair.getPrivate());
            encryptedIv = cipher.doFinal(client.params.getIV());
            // -------------------------------------------------------------------------- sign with client's private key
            final var signature = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
            signature.initSign(client.keyPair.getPrivate());
            signature.update(client.params.getIV());
            ivSignature = signature.sign();
        }
        // ---------------------------------------------------------------------- server receives/decrypts/verify the iv
        {
            // ------------------------------------------------------------------------ decrypt with client's public key
            final var cipher = Cipher.getInstance(ASYMMETRIC_TRANSFORMATION, PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, client.keyPair.getPublic());
            final var decrypted = cipher.doFinal(encryptedIv);
            assertThat(decrypted).isEqualTo(client.params.getIV());
            server.params = new IvParameterSpec(decrypted);
            // ------------------------------------------------------------------------- verify with client's public key
            final var signature = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
            signature.initVerify(client.keyPair.getPublic());
            signature.update(decrypted);
            final var verified = signature.verify(ivSignature);
            assertThat(verified).isTrue();
        }
        // ------------------------------------------------------------------------- client encrypts/signs/sends message
        {
            client.message = new byte[ThreadLocalRandom.current().nextInt(8192)];
            ThreadLocalRandom.current().nextBytes(client.message);
        }
        final byte[] encryptedMessage;
        final byte[] messageSignature;
        {
            // ----------------------------------------------------------------------------- encrypt with the secret key
            final var cipher = Cipher.getInstance(SYMMETRIC_TRANSFORMATION, PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, client.secretKey, client.params);
            encryptedMessage = cipher.doFinal(client.message);
            // -------------------------------------------------------------------------- sign with client's private key
            final var signature = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
            signature.initSign(client.keyPair.getPrivate());
            signature.update(client.message);
            messageSignature = signature.sign();
        }
        // ------------------------------------------------------------------- server receives/decrypts/verifies message
        {
            // ----------------------------------------------------------------------------- decrypt with the secret key
            final var cipher = Cipher.getInstance(SYMMETRIC_TRANSFORMATION, PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, server.secretKey, server.params);
            final var decryptedMessage = cipher.doFinal(encryptedMessage);
            assertThat(decryptedMessage).isEqualTo(client.message);
            // ------------------------------------------------------------------------- verify with client's public key
            final var signature = Signature.getInstance(SIGNATURE_ALGORITHM, PROVIDER);
            signature.initVerify(client.keyPair.getPublic());
            signature.update(decryptedMessage);
            final boolean verified = signature.verify(messageSignature);
            assertThat(verified).isTrue();
        }
    }
}
