package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BufferedBlockCipher_TestUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@NoArgsConstructor(access = AccessLevel.PACKAGE)
@Slf4j
public class JinahyaBufferedBlockCipherUtils_Test {

    private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return _BufferedBlockCipher_TestUtils.getCipherAndParamsArgumentsStream();
    }

    @DisplayName("processBlock(cipher, in, inoff, out, outoff)")
    @Nested
    class ProcessBlockTest {

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return JinahyaBufferedBlockCipherUtils_Test.getCipherAndParamsArgumentsStream();
        }

        @MethodSource("getCipherAndParamsArgumentsStream")
        @ParameterizedTest
        void __(final BufferedBlockCipher cipher, final CipherParameters params) throws InvalidCipherTextException {
            final var blockSize = cipher.getBlockSize();
            final var plain = _Random_TestUtils.newRandomBytes(blockSize);
            final var digest = new SHA256Digest();
            final var mac = new HMac(new SHA1Digest());
            if (params instanceof KeyParameter) {
                mac.init(params);
            } else if (params instanceof ParametersWithIV) {
                mac.init(((ParametersWithIV) params).getParameters());
            } else {
                throw new RuntimeException("not handled: " + params);
            }
            // ------------------------------------------------------------------------------------------------- encrypt
            final byte[] encrypted;
            final var encdigest = new byte[digest.getDigestSize()];
            final var encmac = new byte[mac.getMacSize()];
            {
                cipher.init(true, params);
                {
                    final var out = new byte[blockSize];
                    final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                            cipher,
                            plain,
                            0,
                            plain.length,
                            out,
                            0
                    );
                    assert outlen == out.length;
                    encrypted = Arrays.copyOf(out, outlen);
                }
                {
                    digest.update(plain, 0, plain.length);
                    final var bytes = digest.doFinal(encdigest, 0);
                    assert bytes == encdigest.length;
                }
                {
                    mac.update(plain, 0, plain.length);
                    final var bytes = mac.doFinal(encmac, 0);
                    assert bytes == encmac.length;
                }
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final byte[] decrypted;
            final var decdigest = new byte[digest.getDigestSize()];
            final var decmac = new byte[mac.getMacSize()];
            {
                cipher.init(false, params);
                {
                    final var out = new byte[blockSize];
                    final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                            cipher,
                            encrypted,
                            0,
                            encrypted.length,
                            out,
                            0
                    );
                    assert outlen == out.length;
                    decrypted = Arrays.copyOf(out, outlen);
                }
                {
                    digest.update(decrypted, 0, decrypted.length);
                    final var bytes = digest.doFinal(decdigest, 0);
                    assert bytes == decdigest.length;
                }
                {
                    mac.update(decrypted, 0, decrypted.length);
                    final var bytes = mac.doFinal(decmac, 0);
                    assert bytes == decmac.length;
                }
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decdigest)
                    .as("digest")
                    .isEqualTo(encdigest);
            assertThat(decmac)
                    .as("mac")
                    .isEqualTo(encmac);
        }
    }

    @DisplayName("processBlock(cipher, in, out, inbuf, outbuf, inconsumer, outconsumer")
    @Nested
    class ProcessBlocksTest {

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return JinahyaBufferedBlockCipherUtils_Test.getCipherAndParamsArgumentsStream();
        }

        @MethodSource("getCipherAndParamsArgumentsStream")
        @ParameterizedTest
        void __(final BufferedBlockCipher cipher, final CipherParameters params)
                throws IOException, InvalidCipherTextException {
            final var blockSize = cipher.getBlockSize();
            final var blockCount = ThreadLocalRandom.current().nextInt(128) + 1;
            final var plain = _Random_TestUtils.newRandomBytes(blockCount * blockSize);
            final var digest = new SHA256Digest();
            final var mac = new HMac(new SHA1Digest());
            if (params instanceof KeyParameter) {
                mac.init(params);
            } else if (params instanceof ParametersWithIV) {
                mac.init(((ParametersWithIV) params).getParameters());
            } else {
                throw new RuntimeException("not handled: " + params);
            }
            final var out = new ByteArrayOutputStream(plain.length);
            final var inbuf = new byte[cipher.getBlockSize()];
            final var outbuf = new byte[inbuf.length];
            // ------------------------------------------------------------------------------------------------- encrypt
            final byte[] encrypted;
            final var encdigest = new byte[digest.getDigestSize()];
            final var encmac = new byte[mac.getMacSize()];
            {
                cipher.init(true, params);
                {
                    final var count = JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                            cipher,
                            new ByteArrayInputStream(plain),
                            out,
                            inbuf,
                            outbuf,
                            l -> {
                                digest.update(inbuf, 0, l);
                                mac.update(inbuf, 0, l);
                            },
                            b -> l -> {
                            }
                    );
//                    assert count == blockCount;
                    encrypted = out.toByteArray();
                    out.reset();
                }
                {
                    final var bytes = digest.doFinal(encdigest, 0);
                    assert bytes == encdigest.length;
                }
                {
                    final var bytes = mac.doFinal(encmac, 0);
                    assert bytes == encmac.length;
                }
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final byte[] decrypted;
            final var decdigest = new byte[digest.getDigestSize()];
            final var decmac = new byte[mac.getMacSize()];
            {
                cipher.init(false, params);
                {
                    final var count = JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                            cipher,
                            new ByteArrayInputStream(encrypted),
                            out,
                            inbuf,
                            outbuf,
                            l -> {
                            },
                            b -> l -> {
                                digest.update(b, 0, l);
                                mac.update(b, 0, l);
                            }
                    );
//                    assert count == blockCount;
                    decrypted = out.toByteArray();
                    out.reset();
                }
                {
                    final var bytes = digest.doFinal(decdigest, 0);
                    assert bytes == decdigest.length;
                }
                {
                    final var bytes = mac.doFinal(decmac, 0);
                    assert bytes == decmac.length;
                }
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decdigest).isEqualTo(encdigest);
            assertThat(decmac).isEqualTo(encmac);
        }
    }

    private static void __array(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
        // -------------------------------------------------------------------------------------------------------------
        final byte[] encrypted;
        {
            cipher.init(true, params);
            final var out = new byte[cipher.getOutputSize(plain.length)];
            final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    plain,
                    0,
                    plain.length,
                    out,
                    0
            );
            encrypted = Arrays.copyOf(out, outlen);
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] decrypted;
        {
            cipher.init(false, params);
            final var out = new byte[cipher.getOutputSize(encrypted.length)];
            final var outlen = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    encrypted,
                    0,
                    encrypted.length,
                    out,
                    0
            );
            decrypted = Arrays.copyOf(out, outlen);
        }
        // -----------------------------------------------------------------------------------------------------------------
        assertThat(decrypted).isEqualTo(plain);
    }

    private static void __buffer(final BufferedBlockCipher cipher, final CipherParameters params, final byte[] plain)
            throws Exception {
        // -------------------------------------------------------------------------------------------------------------
        cipher.init(true, params);
        final var encrypted = ByteBuffer.allocate(cipher.getOutputSize(plain.length));
        {
            final var bytes = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    ByteBuffer.wrap(plain),
                    encrypted
            );
        }
        // -------------------------------------------------------------------------------------------------------------
        encrypted.flip();
        cipher.init(false, params);
        final var decrypted = ByteBuffer.allocate(cipher.getOutputSize(encrypted.remaining()));
        {
            final var bytes = JinahyaBufferedBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    encrypted,
                    decrypted
            );
        }
        // -----------------------------------------------------------------------------------------------------------------
        assertThat(decrypted.flip()).isEqualTo(ByteBuffer.wrap(plain));
    }

    private static void __stream(final BufferedBlockCipher cipher, final CipherParameters params,
                                 final byte[] plain)
            throws Exception {
        // -------------------------------------------------------------------------------------------------------------
        final byte[] encrypted;
        {
            cipher.init(true, params);
            final var in = new ByteArrayInputStream(plain);
            final var out = new ByteArrayOutputStream();
            final var bytes = JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    new byte[ThreadLocalRandom.current().nextInt(128) + cipher.getBlockSize()],
                    new byte[ThreadLocalRandom.current().nextInt(128) + cipher.getBlockSize()],
                    l -> {
                    },
                    b -> l -> {
                    }
            );
            assert bytes >= plain.length;
            encrypted = out.toByteArray();
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] decrypted;
        {
            cipher.init(false, params);
            final var in = new ByteArrayInputStream(encrypted);
            final var out = new ByteArrayOutputStream();
            final var bytes = JinahyaBufferedBlockCipherUtils.processAllBytesAndDoFinal(
                    cipher,
                    in,
                    out,
                    new byte[ThreadLocalRandom.current().nextInt(128) + cipher.getBlockSize()],
                    null,
                    l -> {
                    },
                    b -> l -> {
                    }
            );
            assert bytes <= encrypted.length;
            decrypted = out.toByteArray();
        }
        // -----------------------------------------------------------------------------------------------------------------
        assertThat(decrypted).isEqualTo(plain);
    }

    public static void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        __array(cipher, params, plain);
        __buffer(cipher, params, plain);
        __stream(cipher, params, plain);
    }
}