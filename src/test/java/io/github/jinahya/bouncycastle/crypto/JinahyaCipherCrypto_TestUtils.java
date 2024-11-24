package io.github.jinahya.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._Digest_TestUtils;
import _org.bouncycastle.crypto.params._KeyParameters_TestUtils;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.IntFunction;

import static org.assertj.core.api.Assertions.assertThat;

public final class JinahyaCipherCrypto_TestUtils {

    static void __array(final JinahyaCipherCrypto<?> crypto) {
        // ------------------------------------------------------------------------------------------------------- given
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        final var digest = _Digest_TestUtils.newRandomDigest();
        final var mac = new HMac(_Digest_TestUtils.newRandomDigest());
        mac.init(_KeyParameters_TestUtils.getKeyParameters(crypto.getParams()));
        final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> buffunction = b -> o -> l -> {
            digest.update(b, o, l);
            mac.update(b, o, l);
        };
        // ----------------------------------------------------------------------------------------------------- encrypt
        final byte[] encrypted;
        final var encdigest = new byte[digest.getDigestSize()];
        final var encmac = new byte[mac.getMacSize()];
        {
            assertThat(crypto.addInbuffunction(buffunction)).isTrue();
            encrypted = crypto.encrypt(plain);
            assertThat(crypto.removeInbuffunction(buffunction)).isTrue();
            assertThat(digest.doFinal(encdigest, 0)).isEqualTo(encdigest.length);
            assertThat(mac.doFinal(encmac, 0)).isEqualTo(encmac.length);
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        final byte[] decrypted;
        final var decdigest = new byte[digest.getDigestSize()];
        final var decmac = new byte[mac.getMacSize()];
        {
            assertThat(crypto.addOutbuffunction(buffunction)).isTrue();
            decrypted = crypto.decrypt(encrypted);
            assertThat(crypto.removeOutbuffunction(buffunction)).isTrue();
            assertThat(digest.doFinal(decdigest, 0)).isEqualTo(decdigest.length);
            assertThat(mac.doFinal(decmac, 0)).isEqualTo(encmac.length);
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
        assertThat(decdigest).isEqualTo(encdigest);
        assertThat(decmac).isEqualTo(encmac);
    }

    static void __stream(final JinahyaCipherCrypto<?> crypto) throws IOException {
        // ------------------------------------------------------------------------------------------------------- given
        final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
        final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
        final var out = new ByteArrayOutputStream();
        final var digest = ThreadLocalRandom.current().nextBoolean() ? new SHA256Digest() : new SHA1Digest();
        final var mac = new HMac(ThreadLocalRandom.current().nextBoolean() ? new SHA256Digest() : new SHA1Digest());
        mac.init(_KeyParameters_TestUtils.getKeyParameters(crypto.getParams()));
        final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> buffunction = b -> o -> l -> {
            digest.update(b, o, l);
            mac.update(b, o, l);
        };
        // ----------------------------------------------------------------------------------------------------- encrypt
        final byte[] encrypted;
        final var encdigest = new byte[digest.getDigestSize()];
        final var encmac = new byte[mac.getMacSize()];
        {
            assertThat(crypto.addInbuffunction(buffunction)).isTrue();
            assertThat(crypto.encrypt(
                    new ByteArrayInputStream(plain),
                    out,
                    inbuf
            )).isGreaterThanOrEqualTo(plain.length);
            assertThat(crypto.removeInbuffunction(buffunction)).isTrue();
            encrypted = out.toByteArray();
            out.reset();
            assertThat(digest.doFinal(encdigest, 0)).isEqualTo(encdigest.length);
            assertThat(mac.doFinal(encmac, 0)).isEqualTo(encmac.length);
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        final byte[] decrypted;
        final var decdigest = new byte[digest.getDigestSize()];
        final var decmac = new byte[mac.getMacSize()];
        {
            assertThat(crypto.addOutbuffunction(buffunction)).isTrue();
            assertThat(crypto.decrypt(
                    new ByteArrayInputStream(encrypted),
                    out,
                    inbuf
            )).isLessThanOrEqualTo(encrypted.length);
            assertThat(crypto.removeOutbuffunction(buffunction)).isTrue();
            decrypted = out.toByteArray();
            assertThat(digest.doFinal(decdigest, 0)).isEqualTo(decdigest.length);
            assertThat(mac.doFinal(decmac, 0)).isEqualTo(decmac.length);
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).isEqualTo(plain);
        assertThat(decdigest).isEqualTo(encdigest);
        assertThat(decmac).isEqualTo(encmac);
    }

    private JinahyaCipherCrypto_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}