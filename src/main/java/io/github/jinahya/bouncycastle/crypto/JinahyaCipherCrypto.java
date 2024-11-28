package io.github.jinahya.bouncycastle.crypto;

import _java.nio._ByteBufferUtils;
import org.bouncycastle.crypto.CipherParameters;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.IntConsumer;
import java.util.function.IntFunction;

/**
 * An abstract crypto class for a specific type of cipher.
 *
 * @param <CIPHER> cipher type parameter
 * @author Jin Kwon &lt;onacit_at_gmail.com&gt;
 */
@SuppressWarnings({
        "java:S119" // Type parameter names should comply with a naming convention
})
public abstract class JinahyaCipherCrypto<CIPHER>
        implements JinahyaCrypto {

    /**
     * Creates a new instance with specified cipher and initialization parameters.
     *
     * @param cipher the cipher.
     * @param params the initialization parameters for the {@code cipher}.
     * @see #cipher
     * @see #params
     */
    protected JinahyaCipherCrypto(final CIPHER cipher, final CipherParameters params) {
        super();
        this.cipher = Objects.requireNonNull(cipher, "cipher is null");
        this.params = Objects.requireNonNull(params, "params is null");
    }

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public final boolean addInbuffunction(
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> inbuffunction) {
        return inbuffunctions.add(Objects.requireNonNull(inbuffunction, "inbuffunction is null"));
    }

    @Override
    public final boolean removeInbuffunction(
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> inbuffunction) {
        return inbuffunctions.remove(Objects.requireNonNull(inbuffunction, "inbuffunction is null"));
    }

    @Override
    public final boolean addOutbuffunction(
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> outbuffunction) {
        return outbuffunctions.add(
                Objects.requireNonNull(outbuffunction, "outbuffunction is null")
        );
    }

    @Override
    public final boolean removeOutbuffunction(
            final Function<? super byte[], ? extends IntFunction<? extends IntConsumer>> outbuffunction) {
        return outbuffunctions.remove(
                Objects.requireNonNull(outbuffunction, "outbuffunction is null")
        );
    }

    // -----------------------------------------------------------------------------------------------------------------

    @Override
    public final byte[] encrypt(final byte[] in) {
        final var out = encrypt_(in);
        inbuffunctions.forEach(f -> f.apply(in).apply(0).accept(in.length));
        outbuffunctions.forEach(f -> f.apply(out).apply(0).accept(out.length));
        return out;
    }

    protected abstract byte[] encrypt_(byte[] in);

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public final int encrypt(final ByteBuffer input, final ByteBuffer output) {
        final var inpos = input.position();
        final var outpos = output.position();
        final var bytes = encrypt_(input, output);
        {
            final byte[] in;
            final int inoff;
            final var inlen = input.position() - inpos;
            if (input.hasArray()) {
                in = input.array();
                inoff = input.arrayOffset() + inpos;
            } else {
                in = _ByteBufferUtils.get(input, inpos, new byte[inlen]);
                inoff = 0;
            }
            inbuffunctions.forEach(f -> f.apply(in).apply(inoff).accept(inlen));
        }
        {
            final byte[] out;
            final int outoff;
            final var outlen = output.position() - outpos;
            if (output.hasArray()) {
                out = output.array();
                outoff = output.arrayOffset() + outpos;
            } else {
                out = _ByteBufferUtils.get(output, outpos, new byte[outlen]);
                outoff = 0;
            }
            outbuffunctions.forEach(f -> f.apply(out).apply(outoff).accept(outlen));
        }
        return bytes;
    }

    protected abstract int encrypt_(ByteBuffer input, ByteBuffer output);

    // -----------------------------------------------------------------------------------------------------------------

    @Override
    public final byte[] decrypt(final byte[] in) {
        final var out = decrypt_(in);
        inbuffunctions.forEach(f -> f.apply(in).apply(0).accept(in.length));
        outbuffunctions.forEach(f -> f.apply(out).apply(0).accept(out.length));
        return out;
    }

    protected abstract byte[] decrypt_(byte[] in);

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public final int decrypt(final ByteBuffer input, final ByteBuffer output) {
        final var inpos = input.position();
        final var outpos = output.position();
        final var bytes = decrypt_(input, output);
        {
            final byte[] in;
            final int inoff;
            final var inlen = input.position() - inpos;
            if (input.hasArray()) {
                in = input.array();
                inoff = input.arrayOffset() + inpos;
            } else {
                in = _ByteBufferUtils.get(input, inpos, new byte[inlen]);
                inoff = 0;
            }
            inbuffunctions.forEach(f -> f.apply(in).apply(inoff).accept(inlen));
        }
        {
            final byte[] out;
            final int outoff;
            final var outlen = output.position() - outpos;
            if (output.hasArray()) {
                out = output.array();
                outoff = output.arrayOffset() + outpos;
            } else {
                out = _ByteBufferUtils.get(output, outpos, new byte[outlen]);
                outoff = 0;
            }
            outbuffunctions.forEach(f -> f.apply(out).apply(outoff).accept(outlen));
        }
        return bytes;
    }

    protected abstract int decrypt_(ByteBuffer input, ByteBuffer output);

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public final long encrypt(final InputStream in, final OutputStream out, byte[] inbuf)
            throws IOException {
        return encrypt_(
                in,
                out,
                inbuf,
                l -> {
                    inbuffunctions.forEach(f -> {
                        f.apply(inbuf).apply(0).accept(l);
                    });
                },
                b -> l -> {
                    outbuffunctions.forEach(f -> {
                        f.apply(b).apply(0).accept(l);
                    });
                }
        );
    }

    protected abstract long encrypt_(InputStream in, OutputStream out, byte[] inbuf, IntConsumer inlenconsumer,
                                     Function<? super byte[], ? extends IntConsumer> outbuffunction)
            throws IOException;

    // -----------------------------------------------------------------------------------------------------------------
    @Override
    public final long decrypt(final InputStream in, final OutputStream out, byte[] inbuf) throws IOException {
        return decrypt_(
                in,
                out,
                inbuf,
                l -> {
                    inbuffunctions.forEach(f -> {
                        f.apply(inbuf).apply(0).accept(l);
                    });
                },
                b -> l -> {
                    outbuffunctions.forEach(f -> {
                        f.apply(b).apply(0).accept(l);
                    });
                }
        );
    }

    protected abstract long decrypt_(InputStream in, OutputStream out, byte[] inbuf, IntConsumer inlenconsumer,
                                     Function<? super byte[], ? extends IntConsumer> outbuffunction)
            throws IOException;

    // ---------------------------------------------------------------------------------------------------------- cipher

    /**
     * Initialize the {@link #cipher} for specified boolean flag of encryption.
     *
     * @param encryption {@code true} for encryption; {@code false} for decryption.
     */
    protected abstract void initFor(final boolean encryption);

    /**
     * Initialize the {@link #cipher} for encryption.
     */
    protected void initForEncryption() {
        initFor(true);
    }

    /**
     * Initialize the {@link #cipher} for decryption.
     */
    protected void initForDecryption() {
        initFor(false);
    }

    // ---------------------------------------------------------------------------------------------------------- cipher

    // ---------------------------------------------------------------------------------------------------------- params

    /**
     * Returns the value of {@code params} property.
     *
     * @return the value of {@code params} property
     */
    public CipherParameters getParams() {
        return params;
    }

    // -----------------------------------------------------------------------------------------------------------------

    /**
     * a cipher to use.
     */
    protected final CIPHER cipher;

    /**
     * a cipher parameters for initializing {@link #cipher}.
     */
    protected final CipherParameters params;

    // -----------------------------------------------------------------------------------------------------------------
    private final Set<Function<? super byte[], ? extends IntFunction<? extends IntConsumer>>> inbuffunctions
            = new HashSet<>();

    private final Set<Function<? super byte[], ? extends IntFunction<? extends IntConsumer>>> outbuffunctions
            = new HashSet<>();
}
