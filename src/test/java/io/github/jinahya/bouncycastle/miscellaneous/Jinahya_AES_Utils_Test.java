package io.github.jinahya.bouncycastle.miscellaneous;

import _javax.security._Random_TestUtils;
import _org.bouncycastle.crypto._Digest_TestUtils;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;

class Jinahya_AES_Utils_Test {

    @DisplayName("_CBC_PKCS7Padding")
    @Nested
    class _CBC_PKCS7PaddingTest {

        @Test
        void __array() {
            // --------------------------------------------------------------------------------------------------- given
            final var key = _AES___TestUtils.randomKey();
            final var iv = __CBC__TestUtils.newRandomIv(_AES___Constants.BLOCK_BYTES);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            final var digest = _Digest_TestUtils.newRandomDigest();
            final var mac = new HMac(_Digest_TestUtils.newRandomDigest());
            mac.init(new KeyParameter(key));
            // ------------------------------------------------------------------------------------------------- encrypt
            final var encrypted = Jinahya_AES_Utils.encrypt_CBC_PKCS7Padding(key, iv, plain);
            final var decdigest = new byte[digest.getDigestSize()];
            final var decmac = new byte[mac.getMacSize()];
            digest.update(plain, 0, plain.length);
            assertThat(digest.doFinal(decdigest, 0)).isEqualTo(decdigest.length);
            mac.update(plain, 0, plain.length);
            assertThat(mac.doFinal(decmac, 0)).isEqualTo(decmac.length);
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = Jinahya_AES_Utils.decrypt_CBC_PKCS7Padding(key, iv, encrypted);
            final var encdigest = new byte[digest.getDigestSize()];
            final var encmac = new byte[mac.getMacSize()];
            digest.update(plain, 0, plain.length);
            assertThat(digest.doFinal(encdigest, 0)).isEqualTo(encdigest.length);
            mac.update(plain, 0, plain.length);
            assertThat(mac.doFinal(encmac, 0)).isEqualTo(encmac.length);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decdigest).isEqualTo(encdigest);
            assertThat(decmac).isEqualTo(encmac);
        }

        @Test
        void __stream() throws IOException {
            // --------------------------------------------------------------------------------------------------- given
            final var key = _AES___TestUtils.randomKey();
            final var iv = __CBC__TestUtils.newRandomIv(_AES___Constants.BLOCK_BYTES);
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8291));
            final var digest = _Digest_TestUtils.newRandomDigest();
            final var mac = new HMac(_Digest_TestUtils.newRandomDigest());
            mac.init(new KeyParameter(key));
            // ------------------------------------------------------------------------------------------------- encrypt
            final byte[] encrypted;
            final var encdigest = new byte[digest.getDigestSize()];
            final var encmac = new byte[mac.getMacSize()];
            {
                final var out = new ByteArrayOutputStream();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
                final var bytes = Jinahya_AES_Utils.encrypt_CBC_PKCS7Padding(
                        key,
                        iv,
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
                assertThat(bytes).isGreaterThanOrEqualTo(plain.length);
                encrypted = out.toByteArray();
                assertThat(digest.doFinal(encdigest, 0)).isEqualTo(encdigest.length);
                assertThat(mac.doFinal(encmac, 0)).isEqualTo(encmac.length);
            }
            // ------------------------------------------------------------------------------------------------- decrypt
            final byte[] decrypted;
            final var decdigest = new byte[digest.getDigestSize()];
            final var decmac = new byte[mac.getMacSize()];
            {
                final var out = new ByteArrayOutputStream();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
                final var bytes = Jinahya_AES_Utils.decrypt_CBC_PKCS7Padding(
                        key,
                        iv,
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
                assertThat(bytes).isLessThanOrEqualTo(encrypted.length);
                decrypted = out.toByteArray();
                assertThat(digest.doFinal(decdigest, 0)).isEqualTo(decdigest.length);
                assertThat(mac.doFinal(decmac, 0)).isEqualTo(decmac.length);
            }
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decdigest).isEqualTo(encdigest);
            assertThat(decmac).isEqualTo(encmac);
        }
    }

    @DisplayName("_GCM_NoPadding")
    @Nested
    class _GCM_NoPadding_Test {

        @Test
        void __bytes() {
            // --------------------------------------------------------------------------------------------------- given
            final var key = _AES___TestUtils.randomKey();
            final var tLen = __GCM__TestUtils.randomTLen();
            final var iv = __GCM__TestUtils.randomIv();
            final var aad = __GCM__TestUtils.randomAad();
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(8192));
            final var digest = _Digest_TestUtils.newRandomDigest();
            final var mac = new HMac(_Digest_TestUtils.newRandomDigest());
            mac.init(new KeyParameter(key));
            // ------------------------------------------------------------------------------------------------- encrypt
            final var encrypted = Jinahya_AES_Utils.encrypt_GCM_NoPadding(key, tLen, iv, aad, plain);
            final var decdigest = new byte[digest.getDigestSize()];
            final var decmac = new byte[mac.getMacSize()];
            digest.update(plain, 0, plain.length);
            assertThat(digest.doFinal(decdigest, 0)).isEqualTo(decdigest.length);
            mac.update(plain, 0, plain.length);
            assertThat(mac.doFinal(decmac, 0)).isEqualTo(decmac.length);
            // ------------------------------------------------------------------------------------------------- decrypt
            final var decrypted = Jinahya_AES_Utils.decrypt_GCM_NoPadding(key, tLen, iv, aad, encrypted);
            final var encdigest = new byte[digest.getDigestSize()];
            final var encmac = new byte[mac.getMacSize()];
            digest.update(plain, 0, plain.length);
            assertThat(digest.doFinal(encdigest, 0)).isEqualTo(encdigest.length);
            mac.update(plain, 0, plain.length);
            assertThat(mac.doFinal(encmac, 0)).isEqualTo(encmac.length);
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decdigest).isEqualTo(encdigest);
            assertThat(decmac).isEqualTo(encmac);
        }

        @Test
        void __stream() throws IOException {
            // --------------------------------------------------------------------------------------------------- given
            final var key = _AES___TestUtils.randomKey();
            final var tLen = __GCM__TestUtils.randomTLen();
            final var iv = __GCM__TestUtils.randomIv();
            final var aad = __GCM__TestUtils.randomAad();
            final var plain = _Random_TestUtils.newRandomBytes(ThreadLocalRandom.current().nextInt(1048576));
            final var digest = _Digest_TestUtils.newRandomDigest();
            final var mac = new HMac(_Digest_TestUtils.newRandomDigest());
            mac.init(new KeyParameter(key));
            // ---------------------------------------------------------------------------------------------------- when
            final byte[] encrypted;
            final var encdigest = new byte[digest.getDigestSize()];
            final var encmac = new byte[mac.getMacSize()];
            {
                final var in = new ByteArrayInputStream(plain);
                final var out = new ByteArrayOutputStream();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
                final var bytes = Jinahya_AES_Utils.encrypt_GMM_NoPadding(
                        key,
                        tLen,
                        iv,
                        aad,
                        in,
                        out,
                        inbuf,
                        l -> {
                            digest.update(inbuf, 0, l);
                            mac.update(inbuf, 0, l);
                        },
                        b -> l -> {
                        }
                );
                assertThat(bytes).isGreaterThanOrEqualTo(plain.length);
                encrypted = out.toByteArray();
                assertThat(digest.doFinal(encdigest, 0)).isEqualTo(encdigest.length);
                assertThat(mac.doFinal(encmac, 0)).isEqualTo(encmac.length);
            }
            final byte[] decrypted;
            final var decdigest = new byte[digest.getDigestSize()];
            final var decmac = new byte[mac.getMacSize()];
            {
                final var in = new ByteArrayInputStream(encrypted);
                final var out = new ByteArrayOutputStream();
                final var inbuf = new byte[ThreadLocalRandom.current().nextInt(128) + 1];
                final var bytes = Jinahya_AES_Utils.decrypt_GMM_NoPadding(
                        key,
                        tLen,
                        iv,
                        aad,
                        in,
                        out,
                        inbuf,
                        l -> {
                        },
                        b -> l -> {
                            digest.update(b, 0, l);
                            mac.update(b, 0, l);
                        }
                );
                assertThat(bytes).isLessThanOrEqualTo(encrypted.length);
                decrypted = out.toByteArray();
                assertThat(digest.doFinal(decdigest, 0)).isEqualTo(decdigest.length);
                assertThat(mac.doFinal(decmac, 0)).isEqualTo(decmac.length);
            }
            // ---------------------------------------------------------------------------------------------------- then
            assertThat(decrypted).isEqualTo(plain);
            assertThat(decdigest).isEqualTo(encdigest);
            assertThat(decmac).isEqualTo(encmac);
        }
    }
}