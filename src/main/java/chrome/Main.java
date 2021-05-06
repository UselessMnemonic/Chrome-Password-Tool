package chrome;

import crypto.Blob;
import crypto.MasterKey;
import crypto.MasterKeyFile;
import utils.NullPrintStream;
import utils.PasswordDialog;
import utils.Utils;

import java.io.File;
import java.io.PrintStream;
import java.util.List;
import java.util.stream.Collectors;

public class Main {

    private static final String HELP_TEXT =
    "Usage: java -jar Chrome-Password-Tool.jar <user-folder> [--output <out-file>] [--dry-run]\n" +
    "\n" +
    "Arguments:\n" +
    "    <user-folder>   Selects the user profile, for example from an external drive.\n" +
    "\n" +
    "Options:\n" +
    "    --output        Selects a file in which to output the results. It is overwritten if it already exists.\n" +
    "\n" +
    "    --dry-run       Disables all data output, ignoring --output if specified.\n" +
    "\n";

    public static void main(String[] args) throws Exception {

        PrintStream out = System.out;
        File outputFile = null;
        String userPath;
        boolean dryRun = false;

        if (args.length == 0) {
            System.out.print(HELP_TEXT);
            return;
        }

        userPath = args[0];
        if (!userPath.endsWith("\\")) userPath += "\\";

        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--")) {
                arg = arg.substring(2);
                if ("output".equals(arg)) {
                    i++; outputFile = new File(args[i]);
                } else if ("dry-run".equals(arg)) {
                    dryRun = true;
                }
            }
        }

        // Verify arguments
        if (dryRun) {
            out = new NullPrintStream();
        }
        else if (outputFile != null) {
            if (outputFile.exists() && !outputFile.isFile()) {
                System.err.print("The specified output path is not a file.");
                return;
            }
            out = new PrintStream(outputFile);
        }

        // get Chrome data
        LocalState localState;
        LoginData loginData;
        try {
            localState = new LocalState(userPath + "AppData\\Local\\Google\\Chrome\\User Data\\Local State");
            loginData = new LoginData(userPath + "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data");
        } catch (Exception e) {
            System.err.printf("Error getting Chrome blob: %s\n\n", e.getMessage());
            return;
        }

        // find SID and master key
        String sid;
        MasterKeyFile masterKeyFile;
        try {
            sid = Utils.autoSid(userPath);
            System.out.printf("User SID seems to be %s\n\n", sid);
            String mkpath = Utils.findMasterKey(userPath, sid, localState.getKeyBlob());
            System.out.printf("Required Master Key is %s\n\n", mkpath);
            masterKeyFile = new MasterKeyFile(mkpath);
        }
        catch (Exception e) {
            System.err.printf("Error retrieving master key: %s\n\n", e.getMessage());
            return;
        }

        // ask user for password
        String password = PasswordDialog.prompt();
        if (password.length() == 0) {
            System.err.print("Password cannot be left blank.");
            return;
        }

        // decrypt master key
        try {
            masterKeyFile.getMasterKey().decryptWithPassword(sid, password);
        } catch (Exception e) {
            System.err.printf("Error decrypting master key: %s. Make sure your password is correct.\n\n", e.getMessage());
            return;
        }

        System.out.printf("%s\n\n", masterKeyFile);
        System.out.printf("%s\n\n", localState.getKeyBlob());

        // decrypt chrome key
        try {
            localState.getKeyBlob().decrypt(masterKeyFile.getMasterKey());
        } catch (Exception e) {
            System.err.printf("Error decrypting chrome blob: %s. Make sure your password is correct.\n\n", e.getMessage());
            return;
        }

        // show passwords
        List<Account> accounts;
        try {
            accounts = loginData.decrypt(localState.getKeyBlob().getPlaintext());
        }
        catch (Exception e) {
            System.err.printf("Error while decoding passwords: %s. Make sure your password is correct.\n\n", e.getMessage());
            e.printStackTrace();
            return;
        }

        String outputString = accounts.stream()
                .map(a -> a.toString() + "\n")
                .collect(Collectors.joining());

        out.print(outputString);
    }
}
