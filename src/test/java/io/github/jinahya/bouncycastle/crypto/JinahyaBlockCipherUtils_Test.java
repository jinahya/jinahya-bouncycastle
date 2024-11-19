package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class JinahyaBlockCipherUtils_Test {

    private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
        return _BlockCipher_TestUtils.getCipherAndParamsArgumentsStream();
    }

    @DisplayName("processBlock(cipher, in, inoff, out, outoff, inmac, outmac")
    @Nested
    class ProcessBlockTest {

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return JinahyaBlockCipherUtils_Test.getCipherAndParamsArgumentsStream();
        }

        @MethodSource("getCipherAndParamsArgumentsStream")
        @ParameterizedTest
        void __(final BlockCipher cipher, final CipherParameters params) {
            final var blockSize = cipher.getBlockSize();
            final var plain = _Random_TestUtils.newRandomBytes(blockSize);
            final var digest = new SHA256Digest();
            final var mac = new HMac(new SHA1Digest());
            mac.init(params);
            // ------------------------------------------------------------------------------------------------- encrypt
            final byte[] encrypted;
            final byte[] encdigest;
            final byte[] encmac;
            {
                cipher.init(true, params);
                {
                    final var out = new byte[blockSize];
                    final var outlen = JinahyaBlockCipherUtils_.processBlock(
                            cipher,
                            plain,
                            0,
                            out,
                            0,
                            a -> {
                                digest.update(a, 0, a.length);
                                mac.update(a, 0, a.length);
                            },
                            null
                    );
                    assert outlen == out.length;
                    encrypted = Arrays.copyOf(out, outlen);
                }
                {
                    final var d = new byte[digest.getDigestSize()];
                    encdigest = Arrays.copyOf(d, digest.doFinal(d, 0));
                }
                {
                    final var m = new byte[mac.getMacSize()];
                    encmac = Arrays.copyOf(m, mac.doFinal(m, 0));
                }
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final byte[] decrypted;
            final byte[] decdigest;
            final byte[] decmac;
            {
                cipher.init(false, params);
                {
                    final var out = new byte[blockSize];
                    final var outlen = JinahyaBlockCipherUtils.processBlock(
                            cipher,
                            encrypted,
                            0,
                            out,
                            0,
                            null,
                            a -> {
                                digest.update(a, 0, a.length);
                                mac.update(a, 0, a.length);
                            }
                    );
                    assert outlen == out.length;
                    decrypted = Arrays.copyOf(out, outlen);
                }
                {
                    final var d = new byte[digest.getDigestSize()];
                    decdigest = Arrays.copyOf(d, digest.doFinal(d, 0));
                }
                {
                    final var m = new byte[mac.getMacSize()];
                    decmac = Arrays.copyOf(m, mac.doFinal(m, 0));
                }
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decdigest).isEqualTo(encdigest);
            assertThat(decmac).isEqualTo(encmac);
        }
    }

    @DisplayName("processBlock(cipher, in, out, inbuf, outbuf, inmac, outmac")
    @Nested
    class ProcessBlocksTest {

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return JinahyaBlockCipherUtils_Test.getCipherAndParamsArgumentsStream();
        }

        @MethodSource("getCipherAndParamsArgumentsStream")
        @ParameterizedTest
        void __(final BlockCipher cipher, final CipherParameters params) throws IOException {
            final var blockSize = cipher.getBlockSize();
            final var blockCount = ThreadLocalRandom.current().nextInt(128);
            final var plain = _Random_TestUtils.newRandomBytes(blockCount * blockSize);
            final var digest = new SHA256Digest();
            final var mac = new HMac(new SHA1Digest());
            mac.init(params);
            final var out = new ByteArrayOutputStream(plain.length);
            final var inbuf = new byte[cipher.getBlockSize()];
            final var outbuf = new byte[inbuf.length];
            // ------------------------------------------------------------------------------------------------- encrypt
            final byte[] encrypted;
            final byte[] encdigest;
            final byte[] encmac;
            {
                cipher.init(true, params);
                {
                    final var count = JinahyaBlockCipherUtils.processAllBlocks(
                            cipher,
                            new ByteArrayInputStream(plain),
                            out,
                            inbuf,
                            outbuf,
                            a -> {
                                digest.update(a, 0, a.length);
                                mac.update(a, 0, a.length);
                            },
                            null
                    );
                    assert count == blockCount;
                    encrypted = out.toByteArray();
                    out.reset();
                }
                {
                    final var d = new byte[digest.getDigestSize()];
                    encdigest = Arrays.copyOf(d, digest.doFinal(d, 0));
                }
                {
                    final var m = new byte[mac.getMacSize()];
                    encmac = Arrays.copyOf(m, mac.doFinal(m, 0));
                }
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final byte[] decrypted;
            final byte[] decdigest;
            final byte[] decmac;
            {
                cipher.init(false, params);
                {
                    final var count = JinahyaBlockCipherUtils.processAllBlocks(
                            cipher,
                            new ByteArrayInputStream(encrypted),
                            out,
                            inbuf,
                            outbuf,
                            null,
                            a -> {
                                digest.update(a, 0, a.length);
                                mac.update(a, 0, a.length);
                            }
                    );
                    assert count == blockCount;
                    decrypted = out.toByteArray();
                    out.reset();
                }
                {
                    final var d = new byte[digest.getDigestSize()];
                    decdigest = Arrays.copyOf(d, digest.doFinal(d, 0));
                }
                {
                    final var m = new byte[mac.getMacSize()];
                    decmac = Arrays.copyOf(m, mac.doFinal(m, 0));
                }
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decdigest).isEqualTo(encdigest);
            assertThat(decmac).isEqualTo(encmac);
        }
    }
}