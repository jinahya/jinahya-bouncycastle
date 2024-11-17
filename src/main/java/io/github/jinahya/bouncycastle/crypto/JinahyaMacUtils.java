package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.Mac;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

public final class JinahyaMacUtils {

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

    public static <T extends Mac> T updateAll(final T mac, final InputStream in, final byte[] inbuf)
            throws IOException {
        Objects.requireNonNull(mac, "mac is null");
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        return JinahyaMacUtils_.updateAll(mac, in, inbuf);
    }

    private JinahyaMacUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
