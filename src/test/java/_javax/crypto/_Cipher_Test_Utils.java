package _javax.crypto;

import _java.security._Provider__Test_Utils;
import _javax.security._Random_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * .
 *
 * @see <a href="https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html">Java Security
 * Standard Algorithm Names</a> (JDK 21 Documentation)
 */
@Slf4j
public final class _Cipher_Test_Utils {

    public static Stream<String> getStandardAlgorithms() {
        return _Cipher_Test_Constants.STANDARD_ALGORITHMS.stream();
    }

    // -----------------------------------------------------------------------------------------------------------------
    static Stream<Provider.Service> getServiceStream() {
        return _Provider__Test_Utils.getServiceStream(_Cipher_Test_Constants.SERVICE_TYPE);
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._Cipher_Test_Utils#getServiceStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithServices {

    }

    // -----------------------------------------------------------------------------------------------------------------
    static Stream<Provider> getProviderStream() {
        return getServiceStream()
                .map(Provider.Service::getProvider)
                .distinct();
    }

    // -----------------------------------------------------------------------------------------------------------------
    static Stream<String> getSupportedTransformationStream() {
        return _Cipher_Test_Constants.TRANSFORMATIONS_REQUIRED_TO_BE_SUPPORTED.keySet().stream();
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._Cipher_Test_Utils#getSupportedTransformationStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithTransformationsRequiredToBeSupported {

    }

    public static Stream<Arguments> getProviderAndSupportedTransformationArgumentsStream() {
        return getProviderStream().flatMap(p -> getSupportedTransformationStream().map(t -> Arguments.of(p, t)));
    }

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @MethodSource("_javax.crypto._Cipher_Test_Utils#getProviderAndSupportedTransformationArgumentsStream()")
    @ParameterizedTest
    public @interface ParameterizedTestWithProvidersAndSupportedTransformations {

    }

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final Cipher cipher, final Key key, final AlgorithmParameterSpec params, final byte[] aad,
                          final byte[] plain)
            throws Exception {
        // ----------------------------------------------------------------------------------------------------- encrypt
        if (params != null) {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var encrypted = cipher.doFinal(plain);
        // ----------------------------------------------------------------------------------------------------- decrypt
        if (params != null) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var decrypted = cipher.doFinal(encrypted);
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final Cipher cipher, final Key key,
                          final AlgorithmParameterSpec params, final byte[] aad)
            throws Exception {
        assertThat(cipher.getProvider().getName()).isEqualTo(BouncyCastleProvider.PROVIDER_NAME);
        __(cipher, key, params, aad, new byte[0]);
        __(cipher, key, params, aad, new byte[1]);
        __(cipher, key, params, aad, new byte[]{(byte) ThreadLocalRandom.current().nextInt()});
        __(cipher, key, params, aad, _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024)));
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static void __(final Cipher cipher, final Key key,
                          final AlgorithmParameterSpec params, final byte[] aad,
                          final Path dir, final Path plain)
            throws Exception {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(key, "key is null");
        if (!Files.isDirectory(Objects.requireNonNull(dir, "dir is null"))) {
            throw new IllegalArgumentException("dir is not a directory: " + dir);
        }
        if (!Files.isRegularFile(Objects.requireNonNull(plain, "plain is null"))) {
            throw new IllegalArgumentException("plain is not a regular file: " + plain);
        }
        // ------------------------------------------------------------------------------------------------------- given
        final var inbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
        var outbuf = ByteBuffer.allocate(1);
        // ----------------------------------------------------------------------------------------------------- encrypt
        if (params != null) {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var encrypted = Files.createTempFile(dir, null, null);
        try (var in = FileChannel.open(plain, StandardOpenOption.READ);
             var out = FileChannel.open(encrypted, StandardOpenOption.WRITE)) {
            while (in.read(inbuf) != -1) {
                for (inbuf.flip(); ; ) {
                    final var p = inbuf.position(); // TODO: remove!
                    try {
                        final var stored = cipher.update(inbuf, outbuf);
                        assert stored >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        assert inbuf.position() == p; // TODO: remove!
                        System.out.printf("doubling up outbuf.capacity(%1$d)%n", outbuf.capacity());
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    }
                }
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    final var written = out.write(outbuf);
                    assert written >= 0;
                }
                outbuf.clear();
                inbuf.compact();
            }
            for (inbuf.flip(); ; ) {
                try {
                    final var stored = cipher.doFinal(inbuf, outbuf);
                    assert stored >= 0;
                    break;
                } catch (final ShortBufferException sbe) {
                    System.err.printf("doubling up outbuf.capacity(%1$d)%n", outbuf.capacity());
                    outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                }
            }
            for (outbuf.flip(); outbuf.hasRemaining(); ) {
                final var written = out.write(outbuf);
                assert written >= 0;
            }
            out.force(false);
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        inbuf.clear();
        outbuf.clear();
        if (params != null) {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key);
        }
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var decrypted = Files.createTempFile(dir, null, null);
        try (var in = FileChannel.open(encrypted, StandardOpenOption.READ);
             var out = FileChannel.open(decrypted, StandardOpenOption.WRITE)) {
            while (in.read(inbuf) != -1) {
                for (inbuf.flip(); ; ) {
                    final var p = inbuf.position(); // TODO: remove
                    try {
                        final var stored = cipher.update(inbuf, outbuf);
                        assert stored >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        assert inbuf.position() == p; // TODO: remove
                        System.err.printf("doubling up outbuf.capacity, for an intermediate update, from %1$d%n",
                                          outbuf.capacity());
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    }
                }
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    final var written = out.write(outbuf);
                    assert written >= 0;
                }
                outbuf.clear();
                inbuf.compact();
            }
            for (inbuf.flip(); ; ) {
                final var p = inbuf.position(); // TODO: remove
                try {
                    final var stored = cipher.doFinal(inbuf, outbuf);
                    assert stored >= 0;
                    break;
                } catch (final ShortBufferException sbe) {
                    assert inbuf.position() == p; // TODO: remove
                    System.err.printf("doubling up outbuf.capacity, for the finalization, from %1$d%n",
                                      outbuf.capacity());
                    outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                }
            }
            for (outbuf.flip(); outbuf.hasRemaining(); ) {
                final var written = out.write(outbuf);
                assert written >= 0;
            }
            out.force(false);
        }
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).hasSameBinaryContentAs(plain);
    }

    public static void __(final Cipher cipher, final Key key,
                          final AlgorithmParameterSpec params, final byte[] aad,
                          final Path dir)
            throws IOException {
        assertThat(cipher.getProvider().getName()).isEqualTo(BouncyCastleProvider.PROVIDER_NAME);
        _Random_TestUtils.getRandomFileStream(dir).forEach(p -> {
            try {
                __(cipher, key, params, aad, dir, p);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // -----------------------------------------------------------------------------------------------------------------
    private _Cipher_Test_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
