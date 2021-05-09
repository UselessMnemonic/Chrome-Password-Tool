package chrome;

import crypto.MasterKeyFile;
import utils.NullPrintStream;
import utils.PasswordDialog;
import utils.Utils;

import java.io.File;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class Main {

    private static final String HELP_TEXT =
    "Usage: java -jar Chrome-Password-Tool.jar <user-folder> [--brute-force] [--output <out-file>] [--dry-run]\n" +
    "\n" +
    "Arguments:\n" +
    "    <user-folder>   Selects the user profile, for example from an external drive.\n" +
    "\n" +
    "Options:\n" +
    "    --output        Selects a file in which to output the results. It is overwritten if it already exists.\n" +
    "\n" +
    "    --dry-run       Disables all data output, ignoring --output if specified.\n" +
    "\n" +
    "    --brute-force   Tests all available master keys for the user.\n" +
    "\n";

    public static void main(String[] args) throws Exception {

        PrintStream out = System.out;
        PrintStream except = new NullPrintStream();
        File outputFile = null;
        String userPath;
        boolean dryRun = false;
        boolean bruteForce = false;

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
                } else if ("brute-force".equals(arg)) {
                    bruteForce = true;
                } else if ("verbose".equals(arg)) {
                    except = System.err;
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
            e.printStackTrace(except);
            return;
        }

        // find SID and master keys
        String sid;
        List<MasterKeyFile> masterKeyFiles = new ArrayList<>();
        try {
            sid = Utils.autoSid(userPath);
            System.out.printf("User SID seems to be %s\n\n", sid);

            if (bruteForce) {
                List<String> mkpaths = Utils.findAllMasterKeys(userPath, sid);
                for (String mkpath : mkpaths) {
                    masterKeyFiles.add(new MasterKeyFile(mkpath));
                }
            }
            else {
                String mkpath = Utils.findMasterKey(userPath, sid, localState.getKeyBlob());
                masterKeyFiles.add(new MasterKeyFile(mkpath));
            }
        }
        catch (Exception e) {
            System.err.printf("Error retrieving master key: %s\n\n", e.getMessage());
            e.printStackTrace(except);
            return;
        }

        // ask user for password
        String password = PasswordDialog.prompt();
        if (password.length() == 0) {
            System.err.print("Password cannot be left blank.");
            return;
        }

        for (MasterKeyFile masterKeyFile : masterKeyFiles) {
            System.out.printf("Trying Master Key %s\n\n", masterKeyFile.getGuid());

            // decrypt master key
            try {
                masterKeyFile.getMasterKey().decryptWithPassword(sid, password);
            } catch (Exception e) {
                System.err.printf("Error decrypting master key: %s. Make sure your password is correct.\n\n", e.getMessage());
                e.printStackTrace(except);
                continue;
            }

            // decrypt chrome key
            try {
                localState.getKeyBlob().decrypt(masterKeyFile.getMasterKey());
            } catch (Exception e) {
                System.err.printf("Error decrypting chrome blob: %s. Make sure your password is correct.\n\n", e.getMessage());
                e.printStackTrace(except);
                continue;
            }

            System.out.printf("%s\n\n", masterKeyFile);
            System.out.printf("%s\n\n", localState.getKeyBlob());

            // show passwords
            List<Account> accounts;
            try {
                accounts = loginData.decrypt(localState.getKeyBlob().getPlaintext());
            }
            catch (Exception e) {
                System.err.printf("Error while decoding passwords: %s. Make sure your password is correct.\n\n", e.getMessage());
                e.printStackTrace(except);
                continue;
            }

            String outputString = accounts.stream()
                    .map(a -> a.toString() + "\n")
                    .collect(Collectors.joining());

            out.print(outputString);
            return;
        }

        System.err.print("No Master Key worked.\n\n");
    }
}
