package io.github.jinahya.bouncycastle.crypto;

import org.bouncycastle.crypto.Digest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * A class for working with an instance of {@link Digest} interface.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 * @see JinahyaDigestUtils
 */
public class JinahyaDigest {

    /**
     * Creates a new instance with specified digest.
     *
     * @param digest the digest.
     */
    public JinahyaDigest(final Digest digest) {
        super();
        this.digest = Objects.requireNonNull(digest, "digest is null");
        digestSize = this.digest.getDigestSize();
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * .
     *
     * @param in .
     * @return .
     * @see JinahyaDigestUtils#updateAndDoFinal(Digest, byte[], int, int, byte[], int)
     */
    public byte[] digest(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        final var out = new byte[digestSize];
        final var outlen = JinahyaDigestUtils_.updateAndDoFinal(digest, in, 0, in.length, out, 0);
        assert outlen == out.length;
        return out;
    }

    public int digest(final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(input, "input is null");
        if (Objects.requireNonNull(output, "output is null").remaining() < digestSize) {
            throw new IllegalArgumentException(
                    "output.remaining(" + output.remaining() + ") < digest.digestSize(" + digestSize + ")"
            );
        }
        return 0;
    }

    /**
     * .
     *
     * @param in    .
     * @param inbuf .
     * @return .
     * @throws IOException if an I/O error occurs.
     * @see JinahyaDigestUtils#updateAllAndDoFinal(Digest, InputStream, byte[], byte[], int)
     */
    public byte[] digestAll(final InputStream in, final byte[] inbuf) throws IOException {
        Objects.requireNonNull(in, "in is null");
        if (Objects.requireNonNull(inbuf, "inbuf is null").length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        final var out = new byte[digestSize];
        final var outlen = JinahyaDigestUtils_.updateAllAndDoFinal(digest, in, inbuf, out, 0);
        assert outlen == out.length;
        return out;
    }

    // -----------------------------------------------------------------------------------------------------------------
    protected final Digest digest;

    private final int digestSize;
}
