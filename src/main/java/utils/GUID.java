package utils;

import java.util.Arrays;

public class GUID {
    private final String asString;
    private final byte[] bytes;

    public GUID(byte[] bytes) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
        asString = String.format("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                 bytes[3], bytes[2], bytes[1], bytes[0],
                                 bytes[5], bytes[4],
                                 bytes[7], bytes[6],
                                 bytes[8], bytes[9],
                                 bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    }

    public byte[] getBytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    @Override
    public String toString() {
        return asString;
    }
}
