import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.StdCallLibrary;

import java.util.Arrays;
import java.util.List;

public class Protector {

    interface Kernel32 extends StdCallLibrary {
        Pointer LocalFree(Pointer hLocal);
        int GetLastError();
    }

    public interface Crypt32 extends StdCallLibrary {
        class DATA_BLOB extends Structure {
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

        boolean CryptUnprotectData(DATA_BLOB pDataIn, PointerByReference szDataDescr,
                                   DATA_BLOB pOptionalEntropy, Pointer pvReserved,
                                   Pointer pPromptStruct,
                                   int dwFlags,
                                   DATA_BLOB pDataOut);
    }

    private static Protector INSTANCE;
    private Kernel32 kernel32;
    private Crypt32 crypt32;

    private Protector() { }

    public static Protector getInstance() {
        if (INSTANCE == null) {
            Protector newInstance = new Protector();
            newInstance.kernel32 = Native.load("Kernel32", Kernel32.class);
            newInstance.crypt32 = Native.load("Crypt32", Crypt32.class);
            INSTANCE = newInstance;
        }
        return INSTANCE;
    }

    public byte[] unprotect(byte[] data) throws Exception {
        Crypt32.DATA_BLOB pDataIn = new Crypt32.DATA_BLOB(data);
        Crypt32.DATA_BLOB pDataOut = new Crypt32.DATA_BLOB();
        boolean success = crypt32.CryptUnprotectData(pDataIn, null,
                                                     null, null,
                                                     null,
                                                     0,
                                                     pDataOut);
        data = pDataOut.getData();
        if (success) {
            kernel32.LocalFree(pDataOut.pbData);
            return data;
        }
        else {
            throw new Exception(String.format("Error code %d", kernel32.GetLastError()));
        }
    }
}
