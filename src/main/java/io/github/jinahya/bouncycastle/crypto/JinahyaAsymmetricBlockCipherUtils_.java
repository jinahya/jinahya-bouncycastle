package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.nio.ByteBuffer;

final class JinahyaAsymmetricBlockCipherUtils_ {

    // -----------------------------------------------------------------------------------------------------------------
    private static int processBlock(final AsymmetricBlockCipher cipher, final byte[] in, final int inoff,
                                    final int inlen,
                                    final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert inlen >= 0;
        assert inlen <= cipher.getInputBlockSize();
        assert inoff + inlen <= in.length;
        assert out != null;
        assert outoff >= 0;
        final var block = cipher.processBlock(in, inoff, inlen);
        System.arraycopy(block, 0, out, outoff, block.length); // IndexOutOfBoundsException
        return block.length;
    }

    static int processBytes(final AsymmetricBlockCipher cipher, final byte[] in, int inoff, final int inlen,
                            final byte[] out, int outoff)
            throws InvalidCipherTextException {
        assert cipher != null;
        assert in != null;
        assert inoff >= 0;
        assert inlen >= 0;
        assert inoff + inlen <= in.length;
        assert out != null;
        assert outoff >= 0;
        assert outoff <= out.length;
        var bytes = 0;
        final var blocks = JinahyaAsymmetricBlockCipherUtils.getInputBlockCount(cipher, inlen);
        for (int inlen_ = cipher.getInputBlockSize(), i = 0; i < blocks; i++) {
            if (i == blocks - 1) {
                inlen_ = in.length - inoff;
            }
            final var outlen = processBlock(cipher, in, inoff, inlen_, out, outoff);
            inoff += inlen_;
            outoff += outlen;
            bytes += outlen;
        }
        return bytes;
    }

    static int processBytes(final AsymmetricBlockCipher cipher, final ByteBuffer input, final ByteBuffer output)
            throws InvalidCipherTextException {
        assert cipher != null;
        assert input != null;
        assert output != null;
        final byte[] in;
        final int inoff;
        final int inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = new byte[inlen];
//            input.get(0, in); // Java 13
            for (int p = input.position(), i = 0; i < in.length; p++, i++) {
                in[i] = input.get(p);
            }
            inoff = 0;
        }
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[output.remaining()];
            outoff = 0;
        }
        final var outlen = processBytes(cipher, in, inoff, inlen, out, outoff);
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        input.position(input.position() + inlen);
        return outlen;
    }

//    // -----------------------------------------------------------------------------------------------------------------
//    private static boolean readBlock(final InputStream in, final byte[] inbuf, final int inoff, final int bytes)
//            throws IOException {
//        assert in != null;
//        assert in.markSupported();
//        assert inbuf != null;
//        assert bytes > 0;
//        in.mark(bytes);
//        if ((in.readNBytes(inbuf, inoff, bytes)) < bytes) {
//            in.reset();
//            return false;
//        }
//        return true;
//    }
//
//    static boolean processBlock(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out)
//            throws IOException, InvalidCipherTextException {
//        assert cipher != null;
//        assert in != null;
//        assert in.markSupported();
//        assert out != null;
//        final var inbuf = new byte[cipher.getInputBlockSize()];
//        if (!readBlock(in, inbuf, 0, inbuf.length)) {
//            return false;
//        }
//        final var outbuf = cipher.processBlock(inbuf, 0, inbuf.length);
//        out.write(outbuf);
//        return true;
//    }
//
//    // -----------------------------------------------------------------------------------------------------------------
//    private static int readBlocks(final AsymmetricBlockCipher cipher, final InputStream in, final byte[] inbuf)
//            throws IOException {
//        assert cipher != null;
//        assert in != null;
//        assert in.markSupported();
//        assert inbuf != null;
//        int count = 0;
//        {
//            final var inlen = cipher.getInputBlockSize();
//            final int limit = inbuf.length / cipher.getInputBlockSize();
//            for (var inoff = 0; count < limit; count++, inoff += inlen) {
//                if (!readBlock(in, inbuf, inoff, inlen)) {
//                    break;
//                }
//            }
//        }
//        return count;
//    }
//
//    static long processAllBytes(final AsymmetricBlockCipher cipher, final InputStream in, final OutputStream out,
//                                final byte[] inbuf)
//            throws IOException, InvalidCipherTextException {
//        assert cipher != null;
//        assert in != null;
//        assert in.markSupported();
//        assert out != null;
//        assert inbuf != null;
//        assert inbuf.length >= cipher.getInputBlockSize();
//        var count = 0L;
//        int inoff;
//        final var inlen = cipher.getInputBlockSize();
//        for (int blocks; (blocks = readBlocks(cipher, in, inbuf)) > 0; ) {
//            inoff = 0;
//            for (int i = 0; i < blocks; i++) {
//                final var outbuf = cipher.processBlock(inbuf, inoff, inlen);
//                out.write(outbuf);
//                inoff += inlen;
//                count++;
//            }
//        }
//        return count;
//    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAsymmetricBlockCipherUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
