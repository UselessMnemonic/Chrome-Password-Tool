package crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MasterKeyFile {
    private final long version;
    private final String guid;
    private final long policy;

    private final long masterKeyLen;
    private final MasterKey masterKey;

    public MasterKeyFile(String path) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(Files.readAllBytes(Paths.get(path)));
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        version = buffer.getInt();

        buffer.getLong();

        byte[] encodedGUID = new byte[72];
        buffer.get(encodedGUID);
        guid = new String(encodedGUID, StandardCharsets.UTF_16LE);

        buffer.getLong();

        policy = buffer.getInt();

        masterKeyLen = buffer.getLong();
        buffer.getLong();
        buffer.getLong();
        buffer.getLong();

        byte[] masterKeyBytes = new byte[(int) masterKeyLen];
        buffer.get(masterKeyBytes);
        masterKey = new MasterKey(masterKeyBytes);
    }

    public MasterKey getMasterKey() {
        return masterKey;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[Master Key File]").append('\n');
        sb.append("Version:           ").append(version).append('\n');
        sb.append("GUID:              ").append(guid).append('\n');
        sb.append("Policy:            ").append(String.format("0x%02X", policy)).append('\n');
        sb.append("Master Key Length: ").append(masterKeyLen).append('\n');
        sb.append(masterKey.toString().replace("\n", "\n  "));
        return sb.toString();
    }
}
