package io.github.jinahya.bouncycastle.crypto;

import _java.nio._ByteBufferUtils;
import org.bouncycastle.crypto.Digest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
final class JinahyaDigestUtils_ {

    static <T extends Digest> T update(final T digest, final byte[] in, final int inoff, final int inlen) {
        assert digest != null;
        assert in != null;
        assert inoff >= 0;
        assert inlen >= 0;
        assert (inoff + inlen) <= in.length;
        digest.update(in, inoff, inlen);
        return digest;
    }

    static int updateAndDoFinal(final Digest digest, final byte[] in, final int inoff, final int inlen,
                                final byte[] out, final int outoff) {
        assert out != null;
        assert outoff >= 0;
        assert (outoff + digest.getDigestSize()) <= out.length;
        return update(digest, in, inoff, inlen).doFinal(out, outoff);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static <T extends Digest> T updateAll(final T digest, final InputStream in, final byte[] inbuf) throws IOException {
        assert in != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            update(digest, inbuf, 0, r);
        }
        return digest;
    }

    static int updateAllAndDoFinal(final Digest digest, final InputStream in, final byte[] inbuf, final byte[] out,
                                   final int outoff)
            throws IOException {
        assert out != null;
        assert outoff >= 0;
        assert (outoff + digest.getDigestSize()) <= out.length;
        return updateAll(digest, in, inbuf).doFinal(out, outoff);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static <T extends Digest> T update(final T digest, final ByteBuffer input) {
        assert digest != null;
        assert input != null;
        // -------------------------------------------------------------------------------------------------------------
        final byte[] in;
        final int inoff;
        final var inlen = input.remaining();
        if (input.hasArray()) {
            in = input.array();
            inoff = input.arrayOffset() + input.position();
        } else {
            in = _ByteBufferUtils.get(input, input.position(), new byte[input.remaining()]);
            inoff = 0;
        }
        return update(digest, in, inoff, inlen);
    }

    private static int doFinal(final Digest digest, final ByteBuffer output) {
        final byte[] out;
        final int outoff;
        if (output.hasArray()) {
            out = output.array();
            outoff = output.arrayOffset() + output.position();
        } else {
            out = new byte[digest.getDigestSize()];
            outoff = 0;
        }
        final var outlen = digest.doFinal(out, outoff);
        assert outlen == digest.getDigestSize();
        if (output.hasArray()) {
            output.position(output.position() + outlen);
        } else {
            output.put(out, 0, outlen);
        }
        return outlen;
    }

    static int updateAndDoFinal(final Digest digest, final ByteBuffer input, final ByteBuffer output) {
        assert output != null;
        assert output.remaining() >= digest.getDigestSize();
        return doFinal(update(digest, input), output);
    }

    static int updateAllAndDoFinal(final Digest digest, final InputStream in, final byte[] inbuf,
                                   final ByteBuffer output)
            throws IOException {
        assert output != null;
        assert output.remaining() >= digest.getDigestSize();
        return doFinal(updateAll(digest, in, inbuf), output);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaDigestUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
