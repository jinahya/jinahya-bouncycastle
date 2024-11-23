package io.github.jinahya.bouncycastle.crypto;

final class _ApiHelper {

    private static void validate_(final String prefix, final byte[] a, final int off) {
        if (a == null) {
            throw new IllegalArgumentException(prefix + " is null");
        }
        if (off < 0) {
            throw new IllegalArgumentException(prefix + "off(" + off + ") is negative");
        }
    }

    static void validate(final String prefix, final byte[] a, final int off) {
        validate_(prefix, a, off);
        if (a.length > off) {
            throw new IllegalArgumentException(prefix + ".length(" + a.length + ") > " + prefix + "off(" + off + ")");
        }
    }

    static void validate(final String prefix, final byte[] a, final int off, final int len) {
        validate_(prefix, a, off);
        if (len < 0) {
            throw new IllegalArgumentException(prefix + "len(" + len + ") is negative");
        }
        if (a.length < (off + len)) {
            throw new IllegalArgumentException(
                    prefix + ".length(" + a.length + ") " +
                            "< (" + prefix + "off(" + off + ") + " + prefix + "len(" + len + "))"
            );
        }
    }

    private _ApiHelper() {
        throw new AssertionError("instantiation is not allowed");
    }
}
