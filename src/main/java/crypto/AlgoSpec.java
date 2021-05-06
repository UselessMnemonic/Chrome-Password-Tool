package crypto;

import java.util.HashMap;

public class AlgoSpec {
    public final String name;
    public final int keyLength;
    public final int ivLength;
    public final String transformation;
    public final int blockLength;
    public final int digestLength;

    public AlgoSpec(String name, int keyLength, int ivLength, int blockLength, String transformation) {
        this.name = name;
        this.keyLength = keyLength;
        this.ivLength = ivLength;
        this.transformation = transformation;
        this.blockLength = blockLength;
        this.digestLength = 0;
    }

    public AlgoSpec(String name, int digestLength, int blockLength) {
        this.name = name;
        this.digestLength = digestLength;
        this.blockLength = blockLength;
        this.keyLength = 0;
        this.ivLength = 0;
        this.transformation = null;
    }

    private static final HashMap<Integer, AlgoSpec> map = new HashMap<>();
    public static AlgoSpec getAlgorithm(int id) {
        return map.get(id);
    }

    static {
        map.put(0x6603, new AlgoSpec("DESede", 192 / 8, 64 / 8, 64 / 8, "DESede/CBC/PKCS5Padding"));
        map.put(0x6611, new AlgoSpec("AES", 128 / 8, 128 / 8, 128 / 8, "AES/CBC/PKCS5Padding"));
        map.put(0x660e, new AlgoSpec("AES", 128 / 8, 128 / 8, 128 / 8, "AES/CBC/PKCS5Padding"));
        map.put(0x660f, new AlgoSpec("AES", 192 / 8, 128 / 8, 128 / 8, "AES/CBC/PKCS5Padding"));
        map.put(0x6610, new AlgoSpec("AES", 256 / 8, 128 / 8, 128 / 8, "AES/CBC/PKCS5Padding"));
        map.put(0x6601, new AlgoSpec("DES", 64 / 8, 64 / 8, 64 / 8, "DES/CBC/PKCS5Padding"));

        map.put(0x800e, new AlgoSpec("SHA512", 512 / 8, 1024 / 8));
    }
}
