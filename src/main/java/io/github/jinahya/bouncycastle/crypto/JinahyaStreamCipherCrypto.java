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
    protected byte[] encrypt_(final byte[] in) {
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
    protected int encrypt_(final ByteBuffer input, final ByteBuffer output) {
        initForEncryption();
        return JinahyaStreamCipherUtils.processBytes(
                cipher,
                input,
                output
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    protected byte[] decrypt_(final byte[] in) {
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
    protected int decrypt_(final ByteBuffer input, final ByteBuffer output) {
        initForDecryption();
        return JinahyaStreamCipherUtils.processBytes(
                cipher,
                input,
                output
        );
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Override
    protected long encrypt_(final InputStream in, final OutputStream out, final byte[] inbuf,
                            final IntConsumer inlenconsumer,
                            final Function<? super byte[], ? extends IntConsumer> outbuffunction) throws IOException {
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length(" + inbuf.length + ") is zero");
        }
        Objects.requireNonNull(inlenconsumer, "inlenconsumer is null");
        Objects.requireNonNull(outbuffunction, "outbufconsumer is null");
        initForEncryption();
        final var outbuf = new byte[inbuf.length];
        return JinahyaStreamCipherUtils_.processAllBytes(
                cipher,
                in,
                out,
                inbuf,
                outbuf,
                inlenconsumer,
                outbuffunction
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
    protected long decrypt_(final InputStream in, final OutputStream out, final byte[] inbuf,
                            final IntConsumer inlenconsumer,
                            final Function<? super byte[], ? extends IntConsumer> outbuffunction)
            throws IOException {
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length(" + inbuf.length + ") is zero");
        }
        Objects.requireNonNull(inlenconsumer, "inlenconsumer is null");
        Objects.requireNonNull(outbuffunction, "outbufconsumer is null");
        initForDecryption();
        return JinahyaStreamCipherUtils_.processAllBytes(
                cipher,
                in,
                out,
                inbuf,
                new byte[inbuf.length],
                inlenconsumer,
                outbuffunction
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
