package utils;

import crypto.Blob;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class Utils {
    public static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static String autoSid(String path) {
        path += "AppData\\Roaming\\Microsoft\\Protect\\";
        path = (String) Arrays.stream(new File(path).list())
                .filter(p -> p.startsWith("S-1-5-21"))
                .toArray()[0];
        return path;
    }

    public static String findMasterKey(String path, String sid, Blob forBlob) {
        path += "AppData\\Roaming\\Microsoft\\Protect\\" + sid + "\\" + forBlob.getMasterKeyGUID();
        return path;
    }

    public static List<String> findAllMasterKeys(String path, String sid) throws IOException {
        path += "AppData\\Roaming\\Microsoft\\Protect\\" + sid + "\\";
        return Files.list(Paths.get(path))
                .map(Path::toString)
                .filter(s -> !s.contains("Preferred"))
                .collect(Collectors.toList());
    }

    public static String autoMasterKey(String path, String sid) throws IOException {
        path += "AppData\\Roaming\\Microsoft\\Protect\\" + sid + "\\";

        byte[] pref = Files.readAllBytes(Paths.get(path + "Preferred"));
        pref = Arrays.copyOf(pref, 16);
        GUID guid = new GUID(pref);

        return path + guid.toString();
    }

    public static byte[] join(byte[] ipad, byte[] opad) {
        byte[] result = new byte[ipad.length + opad.length];
        System.arraycopy(ipad, 0, result, 0, ipad.length);
        System.arraycopy(opad, 0, result, ipad.length, opad.length);
        return result;
    }
}
