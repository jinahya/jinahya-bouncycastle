package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntConsumer;

public class JinahyaStreamCipherCrypto
        extends JinahyaCipherCrypto<StreamCipher> {

    public JinahyaStreamCipherCrypto(final StreamCipher cipher, final CipherParameters params) {
        super(cipher, params);
    }

    // ---------------------------------------------------------------------------------------------------------- cipher
    @Override
    protected void initFor(final boolean encryption) {
        cipher.init(encryption, params);
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public byte[] encrypt(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        initForEncryption();
        return JinahyaStreamCipherUtils.processBytes(
                cipher,
                in,
                0,
                in.length
        );
    }

    @Override
    public int encrypt(final ByteBuffer input, final ByteBuffer output) {
        initForEncryption();
        return JinahyaStreamCipherUtils.processBytes(
                cipher,
                input,
                output
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public byte[] decrypt(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        initForDecryption();
        return JinahyaStreamCipherUtils.processBytes(
                cipher,
                in,
                0,
                in.length
        );
    }

    @Override
    public int decrypt(final ByteBuffer input, final ByteBuffer output) {
        initForDecryption();
        return JinahyaStreamCipherUtils.processBytes(
                cipher,
                input,
                output
        );
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Override
    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf,
                        final IntConsumer inlenconsumer,
                        final Function<? super byte[], ? extends IntConsumer> outbufconsumer) throws IOException {
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length(" + inbuf.length + ") is zero");
        }
        Objects.requireNonNull(inlenconsumer, "inlenconsumer is null");
        Objects.requireNonNull(outbufconsumer, "outbufconsumer is null");
        initForEncryption();
        final var outbuf = new byte[inbuf.length];
        return JinahyaStreamCipherUtils_.processAllBytes(
                cipher,
                in,
                out,
                inbuf,
                outbuf,
                inlenconsumer,
                outbufconsumer
        );
    }

//    @Override
//    public long encrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
//        Objects.requireNonNull(in, "in is null");
//        Objects.requireNonNull(out, "out is null");
//        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
//            throw new IllegalArgumentException("inbuf.length(" + inbuf.length + ") is zero");
//        }
//        initForEncryption();
//        final var outbuf = new byte[inbuf.length];
//        return JinahyaStreamCipherUtils_.processAllBytes(
//                cipher,
//                in,
//                out,
//                inbuf,
//                outbuf,
//                l -> {
//                },
//                b -> l -> {
//                }
//        );
//    }

    // -----------------------------------------------------------------------------------------------------------------

    @Override
    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf,
                        final IntConsumer inlenconsumer,
                        final Function<? super byte[], ? extends IntConsumer> outbufconsumer)
            throws IOException {
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length(" + inbuf.length + ") is zero");
        }
        Objects.requireNonNull(inlenconsumer, "inlenconsumer is null");
        Objects.requireNonNull(outbufconsumer, "outbufconsumer is null");
        initForDecryption();
        return JinahyaStreamCipherUtils_.processAllBytes(
                cipher,
                in,
                out,
                inbuf,
                new byte[inbuf.length],
                inlenconsumer,
                outbufconsumer
        );
    }

//    @Override
//    public long decrypt(final InputStream in, final OutputStream out, final byte[] inbuf) throws IOException {
//        initForDecryption();
////        return JinahyaStreamCipherUtils.processAllBytes(
////                cipher,
////                in,
////                out,
////                inbuf,
////                null
////        );
//        return -1L;
//    }
}
