package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._BlockCipher_TestUtils;
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

    @DisplayName("processBlock(cipher, in, inoff, out, outoff, inconsumer, outconsumer")
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
            final var encdigest = new byte[digest.getDigestSize()];
            final var encmac = new byte[mac.getMacSize()];
            {
                cipher.init(true, params);
                {
                    final var out = new byte[blockSize];
                    final var outlen = JinahyaBlockCipherUtils.processBlock(
                            cipher,
                            plain,
                            0,
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
                    final var outlen = JinahyaBlockCipherUtils.processBlock(
                            cipher,
                            encrypted,
                            0,
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
            final var encdigest = new byte[digest.getDigestSize()];
            final var encmac = new byte[mac.getMacSize()];
            {
                cipher.init(true, params);
                {
                    final var count = JinahyaBlockCipherUtils.processAllBlocks(
                            cipher,
                            new ByteArrayInputStream(plain),
                            out,
                            inbuf,
                            outbuf,
                            b -> o -> l -> {
                                digest.update(b, o, l);
                                mac.update(b, o, l);
                            },
                            b -> o -> l -> {
                            }
                    );
                    assert count == blockCount;
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
                    final var count = JinahyaBlockCipherUtils.processAllBlocks(
                            cipher,
                            new ByteArrayInputStream(encrypted),
                            out,
                            inbuf,
                            outbuf,
                            b -> o -> l -> {
                            },
                            b -> o -> l -> {
                                digest.update(b, o, l);
                                mac.update(b, o, l);
                            }
                    );
                    assert count == blockCount;
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
}