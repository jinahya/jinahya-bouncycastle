package io.github.jinahya.bouncycastle.crypto;

import _java.nio._ByteBufferUtils;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

final class JinahyaSignerUtils_ {

    static int generateSignature(final Signer signer, final byte[] in, final int inoff, final int inlen,
                                 final byte[] out, final int outoff)
            throws CryptoException {
        assert signer != null;
        assert in != null;
        signer.update(in, inoff, inlen);
        final var signature = signer.generateSignature();
        System.arraycopy(signature, 0, out, outoff, signature.length); // IndexOutOfBoundsException
        return signature.length;
    }

    static boolean verifySignature(final Signer signer, final byte[] in, final int inoff, final int inlen,
                                   final byte[] signature) {
        assert signer != null;
        assert in != null;
        assert signature != null;
        signer.update(in, inoff, inlen);
        return signer.verifySignature(signature);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static int generateSignature(final Signer signer, final InputStream in, final byte[] inbuf, final byte[] out,
                                 final int outoff)
            throws IOException, CryptoException {
        assert signer != null;
        assert in != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        assert out != null;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            signer.update(inbuf, 0, r);
        }
        final var signature = signer.generateSignature();
        System.arraycopy(signature, 0, out, outoff, signature.length); // IndexOutOfBoundsException
        return signature.length;
    }

    static boolean verifySignature(final Signer signer, final InputStream in, final byte[] inbuf,
                                   final byte[] signature)
            throws IOException {
        assert signer != null;
        assert in != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        assert signature != null;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            signer.update(inbuf, 0, r);
        }
        return signer.verifySignature(signature);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static int generateSignature(final Signer signer, final ByteBuffer input, final ByteBuffer output)
            throws CryptoException {
        assert signer != null;
        assert input != null;
        assert output != null;
        final byte[] in;
        final int inoff;
        final int inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = _ByteBufferUtils.get(input, input.position(), new byte[inlen]);
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
        final var outlen = generateSignature(signer, in, inoff, inlen, out, outoff);
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        input.position(input.position() + inlen);
        return outlen;
    }

    static boolean verifySignature(final Signer signer, final ByteBuffer input, final ByteBuffer signature) {
        assert signer != null;
        assert input != null;
        assert signature != null;
        final byte[] in;
        final int inoff;
        final var inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = _ByteBufferUtils.get(input, input.position(), new byte[inlen]);
            inoff = 0;
        }
        final var verified = verifySignature(
                signer,
                in,
                inoff,
                inlen,
                _ByteBufferUtils.get(signature, signature.position(), new byte[signature.remaining()])
        );
        input.position(input.position() + inlen);
        signature.position(signature.position() + signature.remaining());
        return verified;
    }

    // -----------------------------------------------------------------------------------------------------------------
    static int generateSignature(final Signer signer, final InputStream in, final byte[] inbuf,
                                 final ByteBuffer output)
            throws IOException, CryptoException {
        assert signer != null;
        assert in != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        assert output != null;
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[output.remaining()];
            outoff = 0;
        }
        final var outlen = generateSignature(signer, in, inbuf, out, outoff);
        if (outlen > output.remaining()) {
            throw new BufferOverflowException();
        }
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, outoff, outlen);
        }
        return outlen;
    }

    static boolean verifySignature(final Signer signer, final InputStream in, final byte[] inbuf,
                                   final ByteBuffer signature)
            throws IOException {
        assert signer != null;
        assert in != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        assert signature != null;
        final var signature_ = new byte[signature.remaining()];
        if (signature.hasArray()) {
            System.arraycopy(
                    signature.array(),
                    signature.arrayOffset() + signature.position(),
                    signature_,
                    0,
                    signature_.length
            );
        } else {
            _ByteBufferUtils.get(signature, signature.position(), signature_);
        }
        final var verified = verifySignature(signer, in, inbuf, signature_);
        signature.position(signature.position() + signature_.length);
        return verified;
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaSignerUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
