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
     * Returns the digest of specified input byte array.
     *
     * @param in the input byte array.
     * @return the digest of specified input byte array
     * @see JinahyaDigestUtils#updateAndDoFinal(Digest, byte[], int, int, byte[], int)
     */
    public byte[] digest(final byte[] in) {
        Objects.requireNonNull(in, "in is null");
        final var out = new byte[digestSize];
        final var outlen = JinahyaDigestUtils_.updateAndDoFinal(
                digest,
                in,
                0,
                in.length,
                out,
                0,
                digestSize
        );
        assert outlen == out.length;
        return out;
    }

    /**
     * Digests remaining bytes of specified input buffer, and put result to specified output buffer.
     *
     * @param input  the input buffer.
     * @param output the output buffer.
     * @return the number of bytes put on {@code output}.
     */
    public int digest(final ByteBuffer input, final ByteBuffer output) {
        Objects.requireNonNull(input, "input is null");
        JinahyaDigestUtils.requireValid_Output(output, digestSize);
        return JinahyaDigestUtils_.updateAndDoFinal(
                digest,
                input,
                output,
                digestSize
        );
    }

    /**
     * Digests all bytes from specified input stream, and returns the result.
     *
     * @param in    the input stream.
     * @param inbuf a buffer for reading bytes from {@code in}.
     * @return the digest.
     * @throws IOException if an I/O error occurs.
     * @see JinahyaDigestUtils#updateAllAndDoFinal(Digest, InputStream, byte[], byte[], int)
     */
    public byte[] digestAll(final InputStream in, final byte[] inbuf) throws IOException {
        Objects.requireNonNull(in, "in is null");
        JinahyaDigestUtils.requireValid_Inbuf(inbuf);
        final var out = new byte[digestSize];
        final var outlen = JinahyaDigestUtils_.updateAllAndDoFinal(
                digest,
                in,
                inbuf,
                out,
                0,
                digestSize
        );
        assert outlen == out.length;
        return out;
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * The digest instance holds.
     */
    protected final Digest digest;

    /**
     * The digest size of {@link #digest}.
     */
    protected final int digestSize;
}
