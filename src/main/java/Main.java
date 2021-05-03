import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

public class Main {

    private static final String HELP_TEXT =
    "Usage: " + System.getProperty("program.name") + " [-ha] <login-data> <key> [out-file]\n" +
    "\n" +
    "Arguments:\n" +
    "    <login-data> Path to a Chrome passwords file.\n" +
    "                 It should be at \"%%USERPROFILE%%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\"\n" +
    "\n" +
    "    <key>        Value of encrypted_key provided by Local State file.\n" +
    "                 It should be at \"%%USERPROFILE%%\\AppData\\Local\\Google\\Chrome\\User Data\\Local State\"\n" +
    "\n" +
    "    [out-file]   Path to save the results. This file is overwritten if it already exists.\n" +
    "\n" +
    "Options:\n" +
    "    -a  Output all account details.\n" +
    "\n" +
    "    -h  Prints this usage text.\n" +
    "\n";

    public static void main(String[] args) {
        PrintStream outputStream = System.out;
        boolean outputAllData = false, printHelp = false;
        File passwordsFile = null;
        String keyString = null;
        File outputFile = null;

        if (args.length == 0) {
            System.out.print(HELP_TEXT);
            return;
        }

        for (String arg : args) {
            if (arg.startsWith("-")) {
                for (arg = arg.substring(1); !arg.isEmpty(); arg = arg.substring(1)) {
                    switch (arg.charAt(0)) {
                        case 'a': outputAllData = true; break;
                        case 'h': printHelp = true; break;
                    }
                }
            }
            else if (passwordsFile == null) {
                passwordsFile = new File(arg);
            }
            else if (keyString == null) {
                keyString = arg;
            }
            else if (outputFile == null) {
                outputFile = new File(arg);
            }
        }

        if (printHelp) {
            System.out.print(HELP_TEXT);
        }

        if (passwordsFile == null) {
            System.err.print("Path to passwords file must be specified.\n\n");
            return;
        }

        if (!passwordsFile.isFile()) {
            System.err.print("The specified passwords file does not exist or is not a file.\n\n");
            return;
        }

        if (!passwordsFile.canRead()) {
            System.err.print("The specified passwords file cannot be read.\n\n");
            return;
        }

        if (keyString == null || keyString.isEmpty()) {
            System.err.print("You must specify the encryption key.\n\n");
        }

        if (outputFile != null) {
            try {
               outputStream = new PrintStream(outputFile);
            } catch (FileNotFoundException e) {
                System.err.printf("The output file cannot be used: %s\n\n", e.getMessage());
                return;
            }
        }

        byte[] masterKey;
        try {
            masterKey = Base64.getDecoder().decode(keyString);
            masterKey = Arrays.copyOfRange(masterKey, 5, masterKey.length);
        } catch (IllegalArgumentException e) {
            System.err.printf("The provided key is invalid: %s\n\n", e.getMessage());
            return;
        }

        Protector protector;
        try {
            protector = Protector.getInstance();
        } catch (Exception e) {
            System.err.printf("Error loading libraries: %s\n\n", e.getMessage());
            return;
        }

        try {
            masterKey = protector.unprotect(masterKey);
        } catch (Exception e) {
            System.err.printf("Master key recovery failed: %s\n\n", e.getMessage());
            return;
        }

        try {
            final boolean verbose = outputAllData;
            List<Account> accounts = AccountReader.readAccounts(passwordsFile, masterKey);

            String outputString = accounts.stream()
                    .map(a -> a.toString(verbose) + "\n")
                    .collect(Collectors.joining());

            outputStream.print(outputString);
        } catch (Exception e) {
            System.err.printf("Error while decoding passwords: %s", e.getMessage());
        }

        System.out.println();
    }
}
