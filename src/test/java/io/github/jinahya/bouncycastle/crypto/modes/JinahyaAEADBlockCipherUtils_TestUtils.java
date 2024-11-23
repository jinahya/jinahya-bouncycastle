package io.github.jinahya.bouncycastle.crypto.modes;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

final class JinahyaAEADBlockCipherUtils_TestUtils {

    static void processBytesAndDoFinal__(final AEADBlockCipher cipher, final CipherParameters params)
            throws InvalidCipherTextException {
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        // -------------------------------------------------------------------------------------------------------------
        final byte[] encrypted;
        {
            cipher.init(true, params);
            final var out = new byte[cipher.getOutputSize(plain.length)];
            final var outlen = JinahyaAEADBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    plain,
                    0,
                    plain.length,
                    out,
                    0
            );
            assert outlen >= plain.length;
            encrypted = Arrays.copyOfRange(out, 0, outlen);
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] decrypted;
        {
            cipher.init(false, params);
            final var out = new byte[cipher.getOutputSize(encrypted.length)];
            final var outlen = JinahyaAEADBlockCipherUtils.processBytesAndDoFinal(
                    cipher,
                    encrypted,
                    0,
                    encrypted.length,
                    out,
                    0
            );
            assert outlen <= encrypted.length;
            decrypted = Arrays.copyOfRange(out, 0, outlen);
        }
        // -------------------------------------------------------------------------------------------------------------
        assertThat(decrypted)
                .hasSameSizeAs(plain)
                .isEqualTo(plain);
    }

    static void processAllBytesAndDoFinal__(final AEADBlockCipher cipher, final CipherParameters params)
            throws IOException, InvalidCipherTextException {
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        final var out = new ByteArrayOutputStream();
        final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
        final var digest = new SHA1Digest();
        final var mac = new HMac(new SHA256Digest());
        mac.init(_KeyParameters_TestUtils.getKeyParameters(params));
        // -------------------------------------------------------------------------------------------------------------
        final byte[] encrypted;
        final var encdigest = new byte[digest.getDigestSize()];
        final var encmac = new byte[mac.getMacSize()];
        {
            cipher.init(true, params);
            final var outbuf = new byte[cipher.getOutputSize(inbuf.length)];
            final var outlen = JinahyaAEADBlockCipherUtils.processAllBytesAndDoFinal(
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
            assert outlen >= plain.length;
            encrypted = out.toByteArray();
            out.reset();
            {
                final var bytes = digest.doFinal(encdigest, 0);
                assert bytes == encdigest.length;
            }
            {
                final var bytes = mac.doFinal(encmac, 0);
                assert bytes == encmac.length;
            }
        }
        // -------------------------------------------------------------------------------------------------------------
        final byte[] decrypted;
        final var decdigest = new byte[digest.getDigestSize()];
        final var decmac = new byte[mac.getMacSize()];
        {
            cipher.init(false, params);
            final var outbuf = new byte[cipher.getOutputSize(inbuf.length)];
            final var outlen = JinahyaAEADBlockCipherUtils.processAllBytesAndDoFinal(
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
            assert outlen <= encrypted.length;
            decrypted = out.toByteArray();
            {
                final var bytes = digest.doFinal(decdigest, 0);
                assert bytes == decdigest.length;
            }
            {
                final var bytes = mac.doFinal(decmac, 0);
                assert bytes == decmac.length;
            }
        }
        // -------------------------------------------------------------------------------------------------------------
        assertThat(decrypted).isEqualTo(plain);
        assertThat(decdigest).isEqualTo(encdigest);
        assertThat(decmac).isEqualTo(encmac);
    }

    private JinahyaAEADBlockCipherUtils_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}