package crypto;

public enum Algorithm {
    CALG_SHA_512(0x800E, "SHA-512", 64, 128),
    CALG_HMAC(0x8009, "HMAC", 20, 64),
    CALG_SHA1(0x8004, "SHA-1", 20, 64),

    CALG_AES_256(0x6610, "AES-256", 32, 16, 16),
    CALG_3DES(0x6603, "3DES", 21, 8, 8);

    public final int id;
    public final String name;
    public final int hashLen;
    public final int blockLen;
    public final int keyLen;
    public final int ivLen;

    Algorithm(int id, String name, int hashLen, int blockLen) {
        this.id = id;
        this.name = name;
        this.hashLen = hashLen;
        this.blockLen = blockLen;
        this.keyLen = this.ivLen = -1;
    }

    Algorithm(int id, String name, int keyLen, int ivLen, int blockLen) {
        this.id = id;
        this.name = name;
        this.keyLen = keyLen;
        this.ivLen = ivLen;
        this.blockLen = blockLen;
        this.hashLen = -1;
    }

    @Override
    public String toString() {
        return String.format("%s (0x%X)", name, id);
    }

    public static Algorithm getById(int id) throws IllegalArgumentException {
        switch (id) {
            case 0x800E: return CALG_SHA_512;
            case 0x8009: return CALG_HMAC;
            case 0x8004: return CALG_SHA1;
            case 0x6610: return CALG_AES_256;
            case 0x6603: return CALG_3DES;
            default:
                throw new IllegalArgumentException(String.format("Unknown algorithm ID 0x%X", id));
        }
    }
}
