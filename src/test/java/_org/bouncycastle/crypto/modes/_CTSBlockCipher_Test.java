package _org.bouncycastle.crypto.modes;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BlockCipher_TestUtils;
import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import _org.bouncycastle.crypto.params._ParametersWithIV_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CTSBlockCipher;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class _CTSBlockCipher_Test {

    private static Stream<BlockCipher> getBlockCipherStream() {
        return _BlockCipher_TestUtils.getBlockCipherStream();
    }

    @MethodSource({"getBlockCipherStream"})
    @ParameterizedTest
    void __ECB(final BlockCipher blockCipher) throws IOException, InvalidCipherTextException {
        final var cipher = new CTSBlockCipher(blockCipher);
        final var params = _KeyParameters_TestUtils.newRandomInstance(
                cipher.getUnderlyingCipher()
        );
        final var blockSize = cipher.getBlockSize();
        // org.bouncycastle.crypto.DataLengthException: need at least one block of input for CTS
        final var blockCount = ThreadLocalRandom.current().nextInt(1, 128);
        final var plain = _Random_TestUtils.newRandomBytes(blockSize * blockCount);
        // -------------------------------------------------------------------------------------------------------------
        final byte[] encrypted;
        {
            cipher.init(true, params);
            final var inbuf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
            var outbuf = new byte[1];
            final var out = new ByteArrayOutputStream();
            try (var in = new ByteArrayInputStream(plain)) {
                for (int r; (r = in.read(inbuf)) != -1; ) {
                    for (final var uos = cipher.getUpdateOutputSize(r); outbuf.length < uos; ) {
                        outbuf = new byte[outbuf.length << 1];
                    }
                    final var outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
                    out.write(outbuf, 0, outlen);
                    out.flush();
                }
                for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
                    outbuf = new byte[outbuf.length << 1];
                }
                final var outlen = cipher.doFinal(outbuf, 0);
                out.write(outbuf, 0, outlen);
            }
            encrypted = out.toByteArray();
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] decrypted;
        {
            cipher.init(false, params);
            final var inbuf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
            var outbuf = new byte[1];
            final var out = new ByteArrayOutputStream();
            try (var in = new ByteArrayInputStream(encrypted)) {
                for (int r; (r = in.read(inbuf)) != -1; ) {
                    for (final var uos = cipher.getUpdateOutputSize(r); outbuf.length < uos; ) {
                        outbuf = new byte[outbuf.length << 1];
                    }
                    final var outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
                    out.write(outbuf, 0, outlen);
                    out.flush();
                }
                for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
                    outbuf = new byte[outbuf.length << 1];
                }
                final var outlen = cipher.doFinal(outbuf, 0);
                out.write(outbuf, 0, outlen);
            }
            decrypted = out.toByteArray();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted)
                .hasSize(plain.length)
                .isEqualTo(plain);
    }

    @MethodSource({"getBlockCipherStream"})
    @ParameterizedTest
    void __CBC(final BlockCipher blockCipher) throws IOException, InvalidCipherTextException {
        final var cipher = new CTSBlockCipher(CBCBlockCipher.newInstance(blockCipher));
        final var params = _ParametersWithIV_TestUtils.newRandomInstance(
                cipher.getUnderlyingCipher(),
                cipher.getBlockSize()
        );
        final var blockSize = cipher.getBlockSize();
        // org.bouncycastle.crypto.DataLengthException: need at least one block of input for CTS
        final var blockCount = ThreadLocalRandom.current().nextInt(1, 128);
        final var plain = _Random_TestUtils.newRandomBytes(blockSize * blockCount);
        // -------------------------------------------------------------------------------------------------------------
        final byte[] encrypted;
        {
            cipher.init(true, params);
            final var inbuf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
            var outbuf = new byte[1];
            final var out = new ByteArrayOutputStream();
            try (var in = new ByteArrayInputStream(plain)) {
                for (int r; (r = in.read(inbuf)) != -1; ) {
                    for (final var uos = cipher.getUpdateOutputSize(r); outbuf.length < uos; ) {
                        outbuf = new byte[outbuf.length << 1];
                    }
                    final var outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
                    out.write(outbuf, 0, outlen);
                    out.flush();
                }
                for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
                    outbuf = new byte[outbuf.length << 1];
                }
                final var outlen = cipher.doFinal(outbuf, 0);
                out.write(outbuf, 0, outlen);
            }
            encrypted = out.toByteArray();
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] decrypted;
        {
            cipher.init(false, params);
            final var inbuf = new byte[ThreadLocalRandom.current().nextInt(8192) + 1];
            var outbuf = new byte[1];
            final var out = new ByteArrayOutputStream();
            try (var in = new ByteArrayInputStream(encrypted)) {
                for (int r; (r = in.read(inbuf)) != -1; ) {
                    for (final var uos = cipher.getUpdateOutputSize(r); outbuf.length < uos; ) {
                        outbuf = new byte[outbuf.length << 1];
                    }
                    final var outlen = cipher.processBytes(inbuf, 0, r, outbuf, 0);
                    out.write(outbuf, 0, outlen);
                    out.flush();
                }
                for (final var os = cipher.getOutputSize(0); outbuf.length < os; ) {
                    outbuf = new byte[outbuf.length << 1];
                }
                final var outlen = cipher.doFinal(outbuf, 0);
                out.write(outbuf, 0, outlen);
            }
            decrypted = out.toByteArray();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted)
                .hasSize(plain.length)
                .isEqualTo(plain);
    }
}
