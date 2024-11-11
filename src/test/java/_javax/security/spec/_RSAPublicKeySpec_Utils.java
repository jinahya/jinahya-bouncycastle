package _javax.security.spec;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.spec.RSAPublicKeySpec;

public final class _RSAPublicKeySpec_Utils {

    public static File store(final RSAPublicKeySpec key, final File dir) throws IOException {
        final File file = File.createTempFile("tmp", null, dir);
        try (var out = new ObjectOutputStream(new FileOutputStream(file))) {
            out.writeObject(key.getModulus());
            out.writeObject(key.getPublicExponent());
            out.flush();
        }
        return file;
    }

    private _RSAPublicKeySpec_Utils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
