package chrome;

import crypto.Blob;

import java.io.IOException;
import java.nio.file.*;
import java.util.Arrays;
import java.util.Base64;

public class LocalState {

    private final Blob keyBlob;

    public LocalState(String path) throws IOException {
        String line = new String(Files.readAllBytes(Paths.get(path)));
        line = line.substring(line.indexOf("encrypted_key\":\"") + 16);
        line = line.substring(0, line.indexOf('\"'));
        byte[] keyBlob = Base64.getDecoder().decode(line);
        keyBlob = Arrays.copyOfRange(keyBlob, 5, keyBlob.length);
        this.keyBlob = new Blob(keyBlob);
    }

    public Blob getKeyBlob() {
        return keyBlob;
    }
}
