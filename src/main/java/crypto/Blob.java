package crypto;

import utils.GUID;
import utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Blob {

    private final int version;
    private GUID provider;
    private final int mkversion;
    private GUID mkguid;
    private final int flags;
    private final String description;
    private final Algorithm cipherAlgo;
    private final int keyLen;
    private final byte[] salt;
    private final byte[] strong;
    private final Algorithm hashAlgo;
    private final int hashLen;
    private final byte[] hmac;
    private final byte[] cipherText;
    private final byte[] blob;
    private final byte[] sign;
    private byte[] plaintext;

    public Blob(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        version = buffer.getInt();

        byte[] providerBytes = new byte[16];
        buffer.get(providerBytes);
        provider = new GUID(providerBytes);

        int blobStart = buffer.position();

        mkversion = buffer.getInt();

        byte[] mkguidBytes = new byte[16];
        buffer.get(mkguidBytes);
        mkguid = new GUID(mkguidBytes);

        flags = buffer.getInt();

        int descLen = buffer.getInt();
        byte[] descBytes = new byte[descLen];
        buffer.get(descBytes);
        String desc = new String(descBytes, StandardCharsets.UTF_16LE);
        if (desc.equals("\0")) description = "<none>";
        else description = desc;

        cipherAlgo = Algorithm.getById(buffer.getInt());

        keyLen = buffer.getInt();

        int saltLen = buffer.getInt();
        salt = new byte[saltLen];
        buffer.get(salt);

        int strongLen = buffer.getInt();
        strong = new byte[strongLen];
        buffer.get(strong);

        hashAlgo = Algorithm.getById(buffer.getInt());

        hashLen = buffer.getInt();

        int hmacLen = buffer.getInt();
        hmac = new byte[hmacLen];
        buffer.get(hmac);

        int cipherLen = buffer.getInt();
        cipherText = new byte[cipherLen];
        buffer.get(cipherText);

        this.blob = Arrays.copyOfRange(data, blobStart, buffer.position());

        int signLen = buffer.getInt();
        sign = new byte[signLen];
        buffer.get(sign);
    }

    public byte[] decrypt(MasterKey masterKey) throws Exception {
        byte[] sessionkey = CryptSessionKeyWin7(masterKey.getPlainText(), salt, hashAlgo);
        byte[] key = CryptDeriveKey(sessionkey, cipherAlgo, hashAlgo);

        Cipher cipher;
        switch (cipherAlgo) {
            case CALG_AES_256:
                IvParameterSpec parameter = new IvParameterSpec(new byte[16]);
                SecretKeySpec secret = new SecretKeySpec(Arrays.copyOfRange(key, 0, cipherAlgo.keyLen), "AES");
                cipher = Cipher.getInstance("AES/CBC/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, secret, parameter);
                break;

            default:
                throw new UnsupportedOperationException(cipherAlgo.name + " is unsupported");
        }

        byte[] result = cipher.doFinal(cipherText);
        byte padding = result[result.length - 1];
        if (padding <= cipherAlgo.blockLen)
            result = Arrays.copyOfRange(result, 0, result.length - padding);

        byte[] computedSign = CryptSessionKeyWin7(masterKey.getPlainText(), hmac, hashAlgo, blob);
        if (!Arrays.equals(sign, computedSign)) {
            throw new IllegalStateException("Computed sign is incorrect");
        }

        plaintext = result;
        return plaintext;
    }

    public byte[] getPlaintext() {
        return Arrays.copyOfRange(plaintext, 0, plaintext.length);
    }

    public GUID getMasterKeyGUID() {
        return mkguid;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[Blob]").append('\n');
        sb.append("Version:          ").append(version).append('\n');
        sb.append("Provider:         ").append(provider).append('\n');
        sb.append("MK-GUID:          ").append(mkguid).append('\n');
        sb.append("Flags:            ").append(String.format("0x%02X", flags)).append('\n');
        sb.append("Description:      ").append(description).append('\n');
        sb.append("Cipher Algorithm: ").append(cipherAlgo).append('\n');
        sb.append("Hash Algorithm:   ").append(hashAlgo).append('\n');
        sb.append("Salt:             ").append(Utils.toHexString(salt)).append('\n');
        sb.append("HMAC:             ").append(Utils.toHexString(hmac)).append('\n');
        sb.append("Cipher Text:      ").append(Utils.toHexString(cipherText)).append('\n');
        sb.append("Sign:             ").append(Utils.toHexString(sign));
        return sb.toString();
    }

    public static byte[] CryptSessionKeyWin7(byte[] masterKey, byte[] salt, Algorithm hashAlgo) throws Exception {
        return CryptSessionKeyWin7(masterKey, salt, hashAlgo, null);
    }

    public static byte[] CryptSessionKeyWin7(byte[] masterKey, byte[] salt, Algorithm hashAlgo, byte[] verifyBlob) throws Exception {
        if (masterKey.length > 20) {
            masterKey = MessageDigest.getInstance("SHA1").digest(masterKey);
        }

        switch (hashAlgo) {
            case CALG_SHA_512:
                Mac hmac = Mac.getInstance("HmacSHA512");
                SecretKeySpec secret = new SecretKeySpec(masterKey, "HmacSHA512");
                hmac.init(secret);
                hmac.update(salt);
                if (verifyBlob != null) hmac.update(verifyBlob);
                return hmac.doFinal();

            default:
                throw new UnsupportedOperationException(hashAlgo.name + " is unsupported");
        }
    }

    public static byte[] CryptDeriveKey(byte[] h, Algorithm cipherAlgo, Algorithm hashAlgo) throws NoSuchAlgorithmException {
        if (h.length > hashAlgo.blockLen) {
            h = MessageDigest.getInstance(hashAlgo.name).digest(h);
        }

        if (h.length >= cipherAlgo.keyLen) {
            return h;
        }

        h = Arrays.copyOf(h, h.length + hashAlgo.blockLen);

        byte[] ipad = new byte[hashAlgo.blockLen];
        byte[] opad = new byte[hashAlgo.blockLen];
        for (int i = 0 ; i < hashAlgo.blockLen; i++) {
            ipad[i] = (byte) (h[i] ^ 0x36);
            opad[i] = (byte) (h[i] ^ 0x5c);
        }

        ipad = MessageDigest.getInstance(hashAlgo.name).digest(ipad);
        opad = MessageDigest.getInstance(hashAlgo.name).digest(opad);
        return Utils.join(ipad, opad);
    }
}
