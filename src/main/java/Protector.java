import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.util.Arrays;
import java.util.List;

public class Protector {

    public static class DATA_BLOB extends Structure {

        public int cbData;
        public Pointer pbData;

        DATA_BLOB() {
            super();
        }

        DATA_BLOB(byte[] data) {
            super();
            pbData = new Memory(data.length);
            pbData.write(0, data, 0, data.length);
            cbData = data.length;
            allocateMemory();
        }

        protected List<String> getFieldOrder() {
            return Arrays.asList("cbData", "pbData");
        }

        public byte[] getData() {
            return pbData == null ? null : pbData.getByteArray(0, cbData);
        }
    }

    public interface Crypt32 extends StdCallLibrary {

        static Crypt32 getInstance() {
            return Native.load("Crypt32", Crypt32.class);
        }

        boolean CryptUnprotectData(DATA_BLOB pDataIn, PointerByReference szDataDescr,
                                   DATA_BLOB pOptionalEntropy, Pointer pvReserved,
                                   Pointer pPromptStruct,
                                   int dwFlags,
                                   DATA_BLOB pDataOut);
    }

    private static Protector INSTANCE;
    private Crypt32 cryptHandle;

    private Protector() { }

    public static Protector getInstance() {
        if (INSTANCE == null) {
            Protector newInstance = new Protector();
            newInstance.cryptHandle = Crypt32.getInstance();
            INSTANCE = newInstance;
        }
        return INSTANCE;
    }

    public byte[] unprotect(byte[] data) {
        DATA_BLOB pDataIn = new DATA_BLOB(data);
        DATA_BLOB pDataOut = new DATA_BLOB();
        boolean success = cryptHandle.CryptUnprotectData(pDataIn, null,
                null, null,
                null,
                0,
                pDataOut);
        if (!success) throw new RuntimeException();
        return pDataOut.getData();
    }
}
