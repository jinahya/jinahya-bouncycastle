package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.Mac;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

public final class JinahyaMacUtils {

    // -----------------------------------------------------------------------------------------------------------------
    public static <T extends Mac> T update(final T mac, final byte[] in, final int inoff, final int inlen) {
        Objects.requireNonNull(mac, "mac is null");
        Objects.requireNonNull(in, "in is null");
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") is negative");
        }
        if (inlen < 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is negative");
        }
        if ((inoff + inlen) > in.length) {
            throw new IllegalArgumentException(
                    "inoff(" + inoff + ") + inlen(" + inlen + ") > in.length(" + in.length + ")");
        }
        return JinahyaMacUtils_.update(mac, in, inoff, inlen);
    }

    public static int updateAndDoFinal(final Mac mac, final byte[] in, final int inoff, final int inlen,
                                       final byte[] out, final int outoff) {
        Objects.requireNonNull(mac, "mac is null");
        Objects.requireNonNull(in, "in is null");
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") is negative");
        }
        if (inlen < 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is negative");
        }
        if ((inoff + inlen) > in.length) {
            throw new IllegalArgumentException(
                    "inoff(" + inoff + ") + inlen(" + inlen + ") > in.length(" + in.length + ")");
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff <= 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        final var macSize = mac.getMacSize();
        if ((outoff + mac.getMacSize()) > out.length) {
            throw new IllegalArgumentException(
                    "(outoff(" + outoff + ") + mac.macSize(" + macSize + ")) > out.length(" + out.length + ")"
            );
        }
        return JinahyaMacUtils_.updateAndDoFinal(mac, in, inoff, inlen, out, outoff);
    }

    // -----------------------------------------------------------------------------------------------------------------
    public static <T extends Mac> T updateAll(final T mac, final InputStream in, final byte[] inbuf)
            throws IOException {
        Objects.requireNonNull(mac, "mac is null");
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        return JinahyaMacUtils_.updateAll(mac, in, inbuf);
    }

    public static int updateAllAndDoFinal(final Mac mac, final InputStream in, final byte[] inbuf, final byte[] out,
                                          final int outoff)
            throws IOException {
        Objects.requireNonNull(mac, "mac is null");
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff <= 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        final var macSize = mac.getMacSize();
        if ((outoff + mac.getMacSize()) > out.length) {
            throw new IllegalArgumentException(
                    "(outoff(" + outoff + ") + mac.macSize(" + macSize + ")) > out.length(" + out.length + ")"
            );
        }
        return JinahyaMacUtils_.updateAllAndDoFinal(mac, in, inbuf, out, outoff);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaMacUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
