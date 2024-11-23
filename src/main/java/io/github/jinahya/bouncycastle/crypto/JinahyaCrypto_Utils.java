package io.github.jinahya.bouncycastle.crypto;

import java.util.function.Function;
import java.util.function.IntConsumer;

final class JinahyaCrypto_Utils {

    private static IntConsumer emptyInlenconsumer;

    private static Function<byte[], IntConsumer> emptyOutbufconsumer;

    static IntConsumer emptyInlenconsumer() {
        if (emptyInlenconsumer == null) {
            emptyInlenconsumer = l -> {
            };
        }
        return emptyInlenconsumer;
    }

    static Function<byte[], IntConsumer> emptyOutbufconsumer() {
        if (emptyOutbufconsumer == null) {
            emptyOutbufconsumer = b -> l -> {
            };
        }
        return emptyOutbufconsumer;
    }

    private JinahyaCrypto_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
