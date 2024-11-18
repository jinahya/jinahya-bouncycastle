package io.github.jinahya.bouncycastle.crypto;

import io.github.jinahya.bouncycastle.miscellaneous._AES_Constants;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class JinahyaBlockCipherUtilsTest {

    @Nested
    class ProcessBlockTest {

        private static Stream<Arguments> getCipherAndParamsArgumentsStream() {
            return Stream.of(
                    Arguments.of(
                            AESEngine.newInstance(),
                            new KeyParameter(new byte[_AES_Constants.BLOCK_BYTES])
                    )
            );
        }

        @MethodSource("getCipherAndParamsArgumentsStream")
        @ParameterizedTest
        void __(final BlockCipher cipher, final CipherParameters params) {
            final var blockSize = cipher.getBlockSize();
            final var plain = new byte[blockSize];
            final var mac = new HMac(new SHA1Digest());
            mac.init(params);
            // ------------------------------------------------------------------------------------------------- encrypt
            final byte[] encrypted;
            final byte[] encdigest;
            {
                cipher.init(true, params);
                {
                    final var out = new byte[blockSize];
                    final var outlen = JinahyaBlockCipherUtils.processBlock(cipher, plain, 0, out, 0, mac, null);
                    assert outlen == out.length;
                    encrypted = Arrays.copyOf(out, outlen);
                }
                {
                    final var digest = new byte[mac.getMacSize()];
                    encdigest = Arrays.copyOf(digest, mac.doFinal(digest, 0));
                }
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final byte[] decrypted;
            final byte[] decdigest;
            {
                cipher.init(false, params);
                {
                    final var out = new byte[blockSize];
                    final var outlen = JinahyaBlockCipherUtils.processBlock(cipher, encrypted, 0, out, 0, null, mac);
                    assert outlen == out.length;
                    decrypted = Arrays.copyOf(out, outlen);
                }
                {
                    final var digest = new byte[mac.getMacSize()];
                    decdigest = Arrays.copyOf(digest, mac.doFinal(digest, 0));
                }
            }
            // -------------------------------------------------------------------------------------------------- verify
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decdigest).isEqualTo(encdigest);
        }
    }
}