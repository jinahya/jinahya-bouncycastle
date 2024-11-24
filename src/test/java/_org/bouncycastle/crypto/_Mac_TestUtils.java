package _org.bouncycastle.crypto;

import _javax.security._Random_TestUtils;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.util.List;

@Slf4j
public final class _Mac_TestUtils {

    private static final List<Class<? extends Digest>> CLASSES = List.of(
            SHA1Digest.class,
            SHA256Digest.class
    );

    public static Digest newRandomDigest() {
        final var clazz = CLASSES.get(
                _Random_TestUtils.applyRandom(r -> r.nextInt(CLASSES.size()))
        );
        try {
            final var constructor = clazz.getDeclaredConstructor();
            if (!constructor.canAccess(null)) {
                constructor.setAccessible(true);
            }
            return constructor.newInstance();
        } catch (ReflectiveOperationException roe) {
            throw new RuntimeException(roe);
        }
    }

    private _Mac_TestUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
