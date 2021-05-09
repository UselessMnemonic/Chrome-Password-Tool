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
        byte[] pwd = password.getBytes(StandardCharsets.UTF_16LE);
        byte[] pwdHash = MessageDigest.getInstance("SHA1").digest(pwd);
        //System.out.println("Decrypting with hash: " + Utils.toHexString(pwdHash));
        decryptWithPasswordHash(sid, pwdHash);
        return plainText;
    }

    public byte[] decryptWithPasswordHash(String sid, byte[] pwdHash) throws Exception {
        byte[] key = MasterKey.deriveDecryptionKey(pwdHash, sid);
        //System.out.println("Decrypting with derived key: " + Utils.toHexString(key));
        decryptWithKey(key);
        return plainText;
    }

    private void decryptWithKey(byte[] pwdHash) throws Exception {
        byte[] preKey = derivePreKey(pwdHash, this.hashAlg, this.cryptAlg, this.salt, this.rounds);
        //System.out.println("Decrypting with pre key: " + Utils.toHexString(preKey));

        byte[] key = Arrays.copyOfRange(preKey, 0, cryptAlg.keyLen);
        byte[] iv = Arrays.copyOfRange(preKey, cryptAlg.keyLen, preKey.length);
        iv = Arrays.copyOfRange(iv, 0, cryptAlg.ivLen);

        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec secret = new SecretKeySpec(key, "AES");
        IvParameterSpec parameter = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, secret, parameter);
        byte[] cleartext = cipher.doFinal(this.cipherText);

        byte[] plainText = Arrays.copyOfRange(cleartext, cleartext.length - 64, cleartext.length);
        byte[] hmacSalt = Arrays.copyOfRange(cleartext, 0, 16);
        byte[] expectedHmac = Arrays.copyOfRange(cleartext, 16, 16 + hashAlg.hashLen);

        // TODO Implement for other hashes
        Mac hmac = Mac.getInstance("HmacSHA512");
        hmac.init(new SecretKeySpec(pwdHash, "HmacSHA512"));
        hmac.update(hmacSalt);

        Mac rv = Mac.getInstance("HmacSHA512");
        rv.init(new SecretKeySpec(hmac.doFinal(), "HmacSHA512"));
        rv.update(plainText);
        byte[] computedHmac = rv.doFinal();

        if (!Arrays.equals(computedHmac, expectedHmac)) {
            throw new IllegalStateException("Computed hash does not equal expected hash");
        }

        this.plainText = plainText;
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

    private static byte[] derivePreKey(byte[] shaBytes, Algorithm hashAlg, Algorithm cryptAlg, byte[] salt, int rounds) throws Exception {
        char[] password = new char[shaBytes.length];
        for (int i = 0; i < shaBytes.length; i++) password[i] = (char) shaBytes[i];

        SecretKeyFactory factory;
        PBEKeySpec keySpec;
        switch (hashAlg) {
            case CALG_SHA_512: //!
                Mac hmac = Mac.getInstance("HmacSHA512");
                PBKDF2 df = new PBKDF2(hmac, shaBytes, salt, rounds);
                return df.GetBytes(cryptAlg.keyLen + cryptAlg.ivLen);

            case CALG_HMAC:
                factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                keySpec = new PBEKeySpec(password, salt, rounds, hashAlg.keyLen + cryptAlg.blockLen);
                return factory.generateSecret(keySpec).getEncoded();

            default:
                throw new IllegalArgumentException(String.format("Unsupported hashing algorithm %s", hashAlg));
        }
    }

    private static byte[] deriveDecryptionKey(byte[] pwdHash, String sid) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA1");
        SecretKeySpec secret = new SecretKeySpec(pwdHash, "HmacSHA1");
        hmac.init(secret);
        sid = sid + "\0";
        return hmac.doFinal(sid.getBytes(StandardCharsets.UTF_16LE));
    }
}
