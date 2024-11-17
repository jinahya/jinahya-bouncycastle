package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.Mac;

import java.io.IOException;
import java.io.InputStream;

final class JinahyaMacUtils_ {

    static <T extends Mac> T update(final T mac, final byte[] in, final int inoff, final int inlen) {
        assert mac != null;
        assert in != null;
        assert inoff >= 0;
        assert inlen >= 0;
        assert (inoff + inlen) <= in.length;
        mac.update(in, inoff, inlen);
        return mac;
    }

    static <T extends Mac> T updateAll(final T mac, final InputStream in, final byte[] inbuf) throws IOException {
        assert in != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            update(mac, inbuf, 0, r);
        }
        return mac;
    }

    private JinahyaMacUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
