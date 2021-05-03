public abstract class Protector {

    public static Protector getInstance() {
        return DPAPI.getInstance();
    }

    public abstract byte[] unprotect(byte[] data);
}