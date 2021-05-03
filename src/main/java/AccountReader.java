import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AccountReader {

    public static List<Account> readAccounts(File passwordsFile, byte[] masterKey) throws Exception {
        ArrayList<Account> results = new ArrayList<>();

        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:"+passwordsFile.getAbsolutePath())) {
            ResultSet resultSet = connection.createStatement().executeQuery("SELECT * FROM logins");
            while (resultSet.next()) {
                Account account = new Account();
                account.usernameValue = resultSet.getString("username_value");
                account.passwordValue = AccountReader.decodePassword(resultSet.getBytes("password_value"), masterKey);
                account.originUrl = resultSet.getString("origin_url");
                account.timesUsed = resultSet.getInt("times_used");
                account.blacklisted = resultSet.getInt("blacklisted_by_user") == 1;
                results.add(account);
            }
        } catch (Exception e) {
            throw e;
        }
        return results;
    }

    private static String decodePassword(byte[] passwordValue, byte[] masterKey) throws Exception {
        byte[] iv = new byte[12];
        System.arraycopy(passwordValue, 3, iv, 0, 12);

        byte[] encrypted = Arrays.copyOfRange(passwordValue, 15, passwordValue.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(masterKey, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] result = cipher.doFinal(encrypted);

        return new String(result, StandardCharsets.UTF_8);
    }
}
