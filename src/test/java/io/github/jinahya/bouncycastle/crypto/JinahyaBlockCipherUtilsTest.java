package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

public class JinahyaBlockCipherUtilsTest {

    public static void __(final BlockCipher cipher, final CipherParameters params) throws IOException {
        final var plain = new byte[ThreadLocalRandom.current().nextInt(8192)];
        // -------------------------------------------------------------------------------------------------------------
        {
            cipher.init(true, params);
            final var in = new ByteArrayInputStream(plain);
            final var out = new ByteArrayOutputStream();
            final var blocks = JinahyaBlockCipherUtils.processAllBlocks(
                    cipher,
                    in,
                    out,
                    new byte[cipher.getBlockSize()],
                    new byte[cipher.getBlockSize()]
            );
            assertThat(blocks).isEqualTo(plain.length / cipher.getBlockSize());
            final var bytes = out.toByteArray();
            if (blocks > 0) {
                assertThat(bytes.length % blocks).isZero();
            }
            assertThat(bytes.length / cipher.getBlockSize()).isEqualTo(blocks);
        }
    }
}