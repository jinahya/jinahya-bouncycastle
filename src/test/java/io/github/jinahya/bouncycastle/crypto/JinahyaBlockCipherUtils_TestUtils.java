package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

final class JinahyaBlockCipherUtils_TestUtils {

    static void processBlock__(final BlockCipher cipher, final CipherParameters params) {
        final var blockSize = cipher.getBlockSize();
        final var plain = _Random_TestUtils.newRandomBytes(blockSize);
        final var digest = ThreadLocalRandom.current().nextBoolean() ? new SHA256Digest() : new SHA1Digest();
        final var mac = new HMac(new SHA1Digest());
        mac.init(_KeyParameters_TestUtils.getKeyParameters(params));
        // ----------------------------------------------------------------------------------------------------- encrypt
        final byte[] encrypted;
        final var encdigest = new byte[digest.getDigestSize()];
        final var encmac = new byte[mac.getMacSize()];
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
        // ----------------------------------------------------------------------------------------------------- decrypt
        final byte[] decrypted;
        final var decdigest = new byte[digest.getDigestSize()];
        final var decmac = new byte[mac.getMacSize()];
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
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).isEqualTo(plain);
        assertThat(decdigest).isEqualTo(encdigest);
        assertThat(decmac).isEqualTo(encmac);
    }

    static void processAllBlocks__(final BlockCipher cipher, final CipherParameters params) throws IOException {
        final var blockSize = cipher.getBlockSize();
        final var blockCount = ThreadLocalRandom.current().nextInt(128);
        final var plain = _Random_TestUtils.newRandomBytes(blockCount * blockSize);
        final var out = new ByteArrayOutputStream(plain.length);
        final var inbuf = new byte[cipher.getBlockSize()];
        final var outbuf = new byte[inbuf.length];
        final var digest = new SHA256Digest();
        final var mac = new HMac(new SHA1Digest());
        mac.init(_KeyParameters_TestUtils.getKeyParameters(params));
        // ----------------------------------------------------------------------------------------------------- encrypt
        final byte[] encrypted;
        final var encdigest = new byte[digest.getDigestSize()];
        final var encmac = new byte[mac.getMacSize()];
        cipher.init(true, params);
        {
            final var count = JinahyaBlockCipherUtils.processAllBlocks(
                    cipher,
                    new ByteArrayInputStream(plain),
                    out,
                    inbuf,
                    outbuf,
                    b -> l -> {
                        digest.update(inbuf, 0, l);
                        mac.update(inbuf, 0, l);
                    },
                    b -> l -> {
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
        // ----------------------------------------------------------------------------------------------------- decrypt
        final byte[] decrypted;
        final var decdigest = new byte[digest.getDigestSize()];
        final var decmac = new byte[mac.getMacSize()];
        cipher.init(false, params);
        {
            final var count = JinahyaBlockCipherUtils.processAllBlocks(
                    cipher,
                    new ByteArrayInputStream(encrypted),
                    out,
                    inbuf,
                    outbuf,
                    b -> l -> {
                    },
                    b -> l -> {
                        digest.update(b, 0, l);
                        mac.update(b, 0, l);
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
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).isEqualTo(plain);
        assertThat(decdigest).isEqualTo(encdigest);
        assertThat(decmac).isEqualTo(encmac);
    }

    private JinahyaBlockCipherUtils_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
