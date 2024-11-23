package io.github.jinahya.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.IntConsumer;

/**
 * A utility class for {@link AEADBlockCipher}.
 *
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
final class JinahyaAEADBlockCipherUtils {

    public static int processBytesAndDoFinal(final AEADBlockCipher cipher, final byte[] in, final int inoff,
                                             final int inlen, final byte[] out, final int outoff)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        if (inoff < 0) {
            throw new IllegalArgumentException("inoff(" + inoff + ") is negative");
        }
        if (inlen < 0) {
            throw new IllegalArgumentException("inlen(" + inlen + ") is negative");
        }
        if ((inoff + inlen) > in.length) {
            throw new IllegalArgumentException(
                    "(inoff(" + inoff + ") + inlen(" + inlen + ")) > in.length(" + in.length + ")"
            );
        }
        Objects.requireNonNull(out, "out is null");
        if (outoff < 0) {
            throw new IllegalArgumentException("outoff(" + outoff + ") is negative");
        }
        if (outoff > out.length) {
            throw new IllegalArgumentException("outoff(" + outoff + ") > out.length(" + out.length + ")");
        }
        return JinahyaAEADBlockCipherUtils_.processBytesAndDoFinal(cipher, in, inoff, inlen, out, outoff);
    }

    public static int processBytesAndDoFinal(final AEADBlockCipher cipher, final ByteBuffer input,
                                             final ByteBuffer output)
            throws InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(input, "input is null");
        Objects.requireNonNull(output, "output is null");
        return JinahyaAEADBlockCipherUtils_.processBytesAndDoFinal(cipher, input, output);
    }

    public static long processAllBytesAndDoFinal(final AEADBlockCipher cipher, final InputStream in,
                                                 final OutputStream out, final byte[] inbuf, final byte[] outbuf,
                                                 final IntConsumer inconsumer,
                                                 final Function<? super byte[], ? extends IntConsumer> outconsumer)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(in, "in is null");
        Objects.requireNonNull(out, "out is null");
        Objects.requireNonNull(inbuf, "inbuf is null");
        if (inbuf.length == 0) {
            throw new IllegalArgumentException("inbuf.length is zero");
        }
        Objects.requireNonNull(inconsumer, "inconsumer is null");
        Objects.requireNonNull(outconsumer, "outconsumer is null");
        return JinahyaAEADBlockCipherUtils_.processAllBytesAndDoFinal(
                cipher,
                in,
                out,
                inbuf,
                outbuf,
                inconsumer,
                outconsumer
        );
    }

    // -----------------------------------------------------------------------------------------------------------------
    private JinahyaAEADBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
