package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

public final class JinahyaCipherCrypto_TestUtils {

    static void __stream(final JinahyaCipherCrypto<?> crypto) throws IOException {
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
        final var out = new ByteArrayOutputStream();
        final var digest = ThreadLocalRandom.current().nextBoolean() ? new SHA256Digest() : new SHA1Digest();
        final var mac = new HMac(ThreadLocalRandom.current().nextBoolean() ? new SHA256Digest() : new SHA1Digest());
        mac.init(_KeyParameters_TestUtils.getKeyParameters(crypto.getParams()));
        // ----------------------------------------------------------------------------------------------------- encrypt
        final byte[] encrypted;
        final var encdigest = new byte[digest.getDigestSize()];
        final var encmac = new byte[mac.getMacSize()];
        {
            {
                final var bytes = crypto.encrypt(
                        new ByteArrayInputStream(plain),
                        out,
                        inbuf,
                        l -> {
                            digest.update(inbuf, 0, l);
                            mac.update(inbuf, 0, l);
                        },
                        b -> l -> {
                        }
                );
                assert bytes >= plain.length;
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
        // ----------------------------------------------------------------------------------------------------- decrypt
        final byte[] decrypted;
        final var decdigest = new byte[digest.getDigestSize()];
        final var decmac = new byte[mac.getMacSize()];
        {
            {
                final var bytes = crypto.decrypt(
                        new ByteArrayInputStream(encrypted),
                        out,
                        inbuf,
                        l -> {
                        },
                        b -> l -> {
                            digest.update(b, 0, l);
                            mac.update(b, 0, l);
                        }
                );
                assert bytes <= encrypted.length;
                decrypted = out.toByteArray();
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
        // ------------------------------------------------------------------------------------------------------ verify
        assertThat(decrypted).isEqualTo(plain);
        assertThat(decdigest).isEqualTo(encdigest);
        assertThat(decmac).isEqualTo(encmac);
    }

    private JinahyaCipherCrypto_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}