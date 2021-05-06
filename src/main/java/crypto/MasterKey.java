package crypto;

import utils.Utils;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public class MasterKey {

    private final int version;
    private final byte[] salt;
    private final int rounds;
    private final Algorithm hashAlg;
    private final Algorithm cryptAlg;
    private final byte[] cipherText;
    private byte[] plainText;

    public MasterKey(byte[] masterKeyBytes) {
        ByteBuffer buffer = ByteBuffer.wrap(masterKeyBytes);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        version = buffer.getInt();

        salt = new byte[16];
        buffer.get(salt);

        rounds = buffer.getInt();

        hashAlg = Algorithm.getById(buffer.getInt());

        cryptAlg = Algorithm.getById(buffer.getInt());

        cipherText = new byte[buffer.remaining()];
        buffer.get(cipherText);
    }

    public byte[] decryptWithPassword(String sid, String password) throws Exception {
        if (plainText == null) {
            byte[] pwd = password.getBytes(StandardCharsets.UTF_16LE);
            byte[] pwdHash = MessageDigest.getInstance("SHA1").digest(pwd);
            //System.out.println("Decrypting with hash: " + Utils.toHexString(pwdHash));
            decryptWithPasswordHash(sid, pwdHash);
        }
        return plainText;
    }

    public byte[] decryptWithPasswordHash(String sid, byte[] pwdHash) throws Exception {
        if (plainText == null) {
            byte[] key = MasterKey.deriveDecryptionKey(pwdHash, sid);
            //System.out.println("Decrypting with derived key: " + Utils.toHexString(key));
            plainText = MasterKey.decrypt(hashAlg, key, salt, rounds, cryptAlg, cipherText);
        }
        return plainText;
    }

    public byte[] getPlainText() {
        return Arrays.copyOf(plainText, plainText.length);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("**Master Key**").append('\n');
        sb.append("Version:              ").append(version).append('\n');
        sb.append("Salt:                 ").append(Utils.toHexString(salt)).append('\n');
        sb.append("Rounds:               ").append(rounds).append('\n');
        sb.append("Hash Algorithm:       ").append(hashAlg.toString()).append('\n');
        sb.append("Encryption Algorithm: ").append(cryptAlg.toString()).append('\n');
        sb.append("Encrypted Key:        ").append(Utils.toHexString(cipherText));
        return sb.toString();
    }

    private static byte[] decrypt(Algorithm hashAlg, byte[] shaBytes, byte[] salt, int rounds, Algorithm cryptAlg, byte[] cipherText) throws Exception {
        byte[] preKey = derivePreKey(shaBytes, hashAlg, cryptAlg, salt, rounds);
        //System.out.println("Decrypting with pre key: " + Utils.toHexString(preKey));

        Cipher cipher;
        switch (cryptAlg) {
            case CALG_AES_256:
                if (hashAlg == Algorithm.CALG_SHA_512) { //!
                    byte[] iv = new byte[16];
                    System.arraycopy(preKey, 32, iv, 0, iv.length);

                    byte[] key = new byte[32];
                    System.arraycopy(preKey, 0, key, 0, key.length);

                    IvParameterSpec parameter = new IvParameterSpec(iv);
                    SecretKeySpec secret = new SecretKeySpec(key, "AES");
                    cipher = Cipher.getInstance("AES/CBC/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, secret, parameter);

                    byte[] output = cipher.doFinal(cipherText);
                    byte[] plainText = new byte[output.length - 16 - 64];
                    System.arraycopy(output, 16 + 64, plainText, 0, plainText.length);
                    return plainText;
                }
                else throw new IllegalArgumentException(String.format("Cannot mix %s and %s", hashAlg, cryptAlg));

            case CALG_3DES:
                if (hashAlg == Algorithm.CALG_HMAC || hashAlg == Algorithm.CALG_3DES) {
                    byte[] iv = new byte[8];
                    System.arraycopy(preKey, 24, iv, 0, iv.length);

                    byte[] key = new byte[24];
                    System.arraycopy(preKey, 0, key, 0, key.length);

                    IvParameterSpec parameter = new IvParameterSpec(iv);
                    SecretKeySpec secret = new SecretKeySpec(key, "3DES");
                    cipher = Cipher.getInstance("3DES/CBC/ZeroBytePadding");
                    cipher.init(Cipher.DECRYPT_MODE, secret, parameter);

                    byte[] output = cipher.doFinal(cipherText);
                    byte[] plainText = new byte[64];
                    System.arraycopy(output, 40, plainText, 0, plainText.length);
                    return plainText;
                }
                else throw new IllegalArgumentException(String.format("Cannot mix %s and %s", hashAlg, cryptAlg));

            default:
                throw new IllegalArgumentException(String.format("Unsupported encryption algorithm %s", cryptAlg));
        }
    }

    private static byte[] derivePreKey(byte[] shaBytes, Algorithm hashAlg, Algorithm cryptAlg, byte[] salt, int rounds) throws Exception {
        char[] password = new char[shaBytes.length];
        for (int i = 0; i < shaBytes.length; i++) password[i] = (char) shaBytes[i];

        SecretKeyFactory factory;
        PBEKeySpec keySpec;
        switch (hashAlg) {
            case CALG_SHA_512: //!
                Mac hmac = Mac.getInstance("HmacSHA512");
                PBKDF2 df = new PBKDF2(hmac, shaBytes, salt, rounds);
                return df.GetBytes(cryptAlg.keyLen + cryptAlg.blockLen);

            case CALG_HMAC:
                factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                keySpec = new PBEKeySpec(password, salt, rounds, hashAlg.keyLen + cryptAlg.blockLen);
                return factory.generateSecret(keySpec).getEncoded();

            default:
                throw new IllegalArgumentException(String.format("Unsupported hashing algorithm %s", hashAlg));
        }
    }

    private static byte[] deriveDecryptionKey(byte[] pwdhash, String sid) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA1");
        SecretKeySpec secret = new SecretKeySpec(pwdhash, "HmacSHA1");
        hmac.init(secret);
        sid = sid + "\0";
        return hmac.doFinal(sid.getBytes(StandardCharsets.UTF_16LE));
    }
}
