package __symmetric.aes.vanilla;

import _javax.security._Random_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
class AES_GCM_NoPadding_Test {

    // ------------------------------------------------------------------------------------------------------- Algorithm
    private static final String ALGORITHM = "AES";

    private static final String MODE = "GCM";

    private static final String PADDING = "NoPadding";

    private static final String TRANSFORMATION = ALGORITHM + '/' + MODE + '/' + PADDING;

    private static final int BLOCK_SIZE = 128;

    private static IntStream getKeySizesStream() {
        return IntStream.of(128, 192, 256)
                .peek(ks -> {
                    assert ks % (BLOCK_SIZE >> 3) == 0;
                });
    }

    private static IntStream getTLenStream() {
        return IntStream.of(
                128, 120, 112, 104, 96
//                ,
//                64, 32
        );
    }

    // -------------------------------------------------------------------------------------------------------- Security
    private static final String PROVIDER_NAME_SUN_JCE = "SunJCE";

    private static final String PROVIDER_NAME_BOUNCY_CASTLE = "BC";

    @BeforeAll
    static void addBouncyCastleProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterAll
    static void removeBouncyCastleProvider() {
        Security.removeProvider(PROVIDER_NAME_BOUNCY_CASTLE);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private static Stream<Arguments> getProviderKeySizeAndTLenArgumentsStream() {
        return Stream.of(PROVIDER_NAME_SUN_JCE, PROVIDER_NAME_BOUNCY_CASTLE)
                .flatMap(p -> getKeySizesStream().mapToObj(
                        ks -> getTLenStream().mapToObj(tl -> Arguments.of(p, ks, tl))))
                .flatMap(Function.identity());
    }

    // -----------------------------------------------------------------------------------------------------------------
    @MethodSource({"getProviderKeySizeAndTLenArgumentsStream"})
    @ParameterizedTest(name = "[{index}] provider: {0}, keySize: {1}, tLen: {2}")
    void __(final String provider, final int keySize, final int tLen) throws Exception {
        final Cipher cipher;
        {
            if (provider.equals(PROVIDER_NAME_SUN_JCE)) {
                if (ThreadLocalRandom.current().nextBoolean()) {
                    cipher = Cipher.getInstance(TRANSFORMATION);
                } else {
                    cipher = Cipher.getInstance(TRANSFORMATION, provider);
                }
            } else {
                cipher = Cipher.getInstance(TRANSFORMATION, provider);
            }
            assert cipher.getProvider().getName().equals(provider);
        }
        final SecretKeySpec key;
        {
            final var bytes = new byte[keySize >> 3];
            ThreadLocalRandom.current().nextBytes(bytes);
            key = new SecretKeySpec(bytes, ALGORITHM);
        }
        final AlgorithmParameterSpec params;
        {
            final var iv = new byte[BLOCK_SIZE >> 3];
            ThreadLocalRandom.current().nextBytes(iv);
            params = new GCMParameterSpec(tLen, iv);
        }
        final var aad = ThreadLocalRandom.current().nextBoolean()
                ? null
                : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        // ------------------------------------------------------------------------------------------------- encrypt
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var encrypted = cipher.doFinal(plain);
        // ------------------------------------------------------------------------------------------------- decrypt
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        final var decrypted = cipher.doFinal(encrypted);
        // -------------------------------------------------------------------------------------------------- verify
        assertThat(decrypted).isEqualTo(plain);
    }

    @MethodSource({"getProviderKeySizeAndTLenArgumentsStream"})
    @ParameterizedTest(name = "[{index}] provider: {0}, keySize: {1}, tLen: {2}")
    void __stream(final String provider, final int keySize, final int tLen, @TempDir final Path dir) throws Exception {
        final Cipher cipher;
        {
            if (provider.equals(PROVIDER_NAME_SUN_JCE)) {
                if (ThreadLocalRandom.current().nextBoolean()) {
                    cipher = Cipher.getInstance(TRANSFORMATION);
                } else {
                    cipher = Cipher.getInstance(TRANSFORMATION, provider);
                }
            } else {
                cipher = Cipher.getInstance(TRANSFORMATION, provider);
            }
            assert cipher.getProvider().getName().equals(provider);
        }
        final SecretKeySpec key;
        {
            final var bytes = new byte[keySize >> 3];
            ThreadLocalRandom.current().nextBytes(bytes);
            key = new SecretKeySpec(bytes, ALGORITHM);
        }
        final AlgorithmParameterSpec params;
        {
            final var bytes = new byte[BLOCK_SIZE >> 3];
            ThreadLocalRandom.current().nextBytes(bytes);
            params = new GCMParameterSpec(tLen, bytes);
        }
        final var aad = ThreadLocalRandom.current().nextBoolean()
                ? null
                : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        final var plain = File.createTempFile("tmp", null, dir.toFile());
        try (final var out = new FileOutputStream(plain)) {
            final var bytes = new byte[ThreadLocalRandom.current().nextInt(8192)];
            ThreadLocalRandom.current().nextBytes(bytes);
            out.write(bytes);
            out.flush();
        }
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = File.createTempFile("tmp", null, dir.toFile());
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        try (var in = new FileInputStream(plain);
             var out = new CipherOutputStream(new FileOutputStream(encrypted), cipher)) {
            final var buf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
            for (int r; (r = in.read(buf)) != -1; ) {
                out.write(buf, 0, r);
            }
            out.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        final var decrypted = File.createTempFile("tmp", null, dir.toFile());
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        try (var in = new CipherInputStream(new FileInputStream(encrypted), cipher);
             var out = new FileOutputStream(decrypted)) {
            final var buf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
            for (int r; (r = in.read(buf)) != -1; ) {
                out.write(buf, 0, r);
            }
            out.flush();
        }
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted)
                .hasSize(plain.length())
                .hasSameBinaryContentAs(plain);
    }

    @MethodSource({"getProviderKeySizeAndTLenArgumentsStream"})
    @ParameterizedTest(name = "[{index}] provider: {0}, keySize: {1}, tLen: {2}")
    void __channel(final String provider, final int keySize, final int tLen, @TempDir final Path dir) throws Exception {
        final Cipher cipher;
        {
            if (provider.equals(PROVIDER_NAME_SUN_JCE)) {
                if (ThreadLocalRandom.current().nextBoolean()) {
                    cipher = Cipher.getInstance(TRANSFORMATION);
                } else {
                    cipher = Cipher.getInstance(TRANSFORMATION, provider);
                }
            } else {
                cipher = Cipher.getInstance(TRANSFORMATION, provider);
            }
            assert cipher.getProvider().getName().equals(provider);
        }
        final SecretKeySpec key;
        {
            final var bytes = new byte[keySize >> 3];
            ThreadLocalRandom.current().nextBytes(bytes);
            key = new SecretKeySpec(bytes, ALGORITHM);
        }
        final AlgorithmParameterSpec params;
        {
            final var iv = new byte[BLOCK_SIZE >> 3];
            ThreadLocalRandom.current().nextBytes(iv);
            params = new GCMParameterSpec(tLen, iv);
        }
        final var aad = ThreadLocalRandom.current().nextBoolean()
                ? null
                : _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1024));
        final var plain = Files.createTempFile(dir, null, null);
        {
            final var bytes = new byte[ThreadLocalRandom.current().nextInt(8192)];
            ThreadLocalRandom.current().nextBytes(bytes);
            Files.write(plain, bytes);
        }
        // ----------------------------------------------------------------------------------------------------- encrypt
        final var encrypted = Files.createTempFile(dir, null, null);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        try (var in = FileChannel.open(plain, StandardOpenOption.READ);
             var out = FileChannel.open(encrypted, StandardOpenOption.WRITE)) {
            final var inbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
            var outbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
            while (in.read(inbuf) != -1) {
                for (inbuf.flip(); ; ) {
                    final var ip = inbuf.position();
                    final var op = outbuf.position();
                    try {
                        final var updated = cipher.update(inbuf, outbuf);
                        assert updated >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        assert inbuf.position() == ip;
                        assert outbuf.position() == op;
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    }
                }
                assert !inbuf.hasRemaining();
                inbuf.clear();
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    final var written = out.write(outbuf);
                    assert written >= 0;
                }
                outbuf.clear();
            }
            assert inbuf.remaining() == inbuf.capacity();
            assert outbuf.remaining() == outbuf.capacity();
            for (inbuf.flip(); ; ) {
                final var ip = inbuf.position();
                final var op = outbuf.position();
                try {
                    final var finalized = cipher.doFinal(inbuf, outbuf);
                    assert finalized >= 0;
                    break;
                } catch (final ShortBufferException sbe) {
                    assert inbuf.position() == ip;
                    assert outbuf.position() == op;
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
        final var decrypted = Files.createTempFile(dir, null, null);
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        try (var in = FileChannel.open(encrypted, StandardOpenOption.READ);
             var out = FileChannel.open(decrypted, StandardOpenOption.WRITE)) {
            final var inbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
            var outbuf = ByteBuffer.allocate(ThreadLocalRandom.current().nextInt(1024) + 1);
            while (in.read(inbuf) != -1) {
                for (inbuf.flip(); ; ) {
                    final var ip = inbuf.position();
                    final var op = outbuf.position();
                    assert outbuf.remaining() == outbuf.capacity();
                    try {
                        final var updated = cipher.update(inbuf, outbuf);
                        assert updated >= 0;
                        break;
                    } catch (final ShortBufferException sbe) {
                        assert inbuf.position() == ip;
                        assert outbuf.position() == op;
                        outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                        assert outbuf.remaining() == outbuf.capacity();
                    }
                }
                inbuf.compact();
                assert inbuf.position() == 0;
                for (outbuf.flip(); outbuf.hasRemaining(); ) {
                    final var written = out.write(outbuf);
                    assert written >= 0;
                }
                outbuf.clear();
            }
            assert inbuf.remaining() == inbuf.capacity();
            assert outbuf.remaining() == outbuf.capacity();
            for (inbuf.flip(); ; ) {
                final var ip = inbuf.position();
                final var op = outbuf.position();
                try {
                    final var finalized = cipher.doFinal(inbuf, outbuf);
                    assert finalized >= 0;
                    break;
                } catch (final ShortBufferException sbe) {
                    assert inbuf.position() == ip;
                    assert outbuf.position() == op;
                    outbuf = ByteBuffer.allocate(outbuf.capacity() << 1);
                    assert outbuf.remaining() == outbuf.capacity();
                }
            }
            for (outbuf.flip(); outbuf.hasRemaining(); ) {
                final var written = out.write(outbuf);
                assert written >= 0;
            }
            out.force(false);
        }
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted)
                .hasSize(Files.size(plain))
                .hasSameBinaryContentAs(plain);
    }
}
