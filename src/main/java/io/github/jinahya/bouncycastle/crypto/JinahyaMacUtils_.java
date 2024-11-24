package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.Mac;

import java.io.IOException;
import java.io.InputStream;

@SuppressWarnings({
        "java:S101" // Class names should comply with a naming convention
})
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

    static int updateAndDoFinal(final Mac mac, final byte[] in, final int inoff, final int inlen, final byte[] out,
                                final int outoff) {
        assert mac != null;
        assert in != null;
        assert inoff >= 0;
        assert inlen >= 0;
        assert (inoff + inlen) <= in.length;
        assert out != null;
        assert outoff >= 0;
        assert (outoff + mac.getMacSize()) <= out.length;
        return update(mac, in, inoff, inlen).doFinal(out, outoff);
    }

    // -----------------------------------------------------------------------------------------------------------------
    static <T extends Mac> T updateAll(final T mac, final InputStream in, final byte[] inbuf) throws IOException {
        assert in != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        for (int r; (r = in.read(inbuf)) != -1; ) {
            update(mac, inbuf, 0, r);
        }
        return mac;
    }

    static int updateAllAndDoFinal(final Mac mac, final InputStream in, final byte[] inbuf, final byte[] out,
                                   final int outoff)
            throws IOException {
        assert in != null;
        assert inbuf != null;
        assert inbuf.length > 0;
        assert out != null;
        assert outoff >= 0;
        assert (outoff + mac.getMacSize()) <= out.length;
        return updateAll(mac, in, inbuf).doFinal(out, outoff);
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaMacUtils_() {
        throw new AssertionError("instantiation is not allowed");
    }
}
