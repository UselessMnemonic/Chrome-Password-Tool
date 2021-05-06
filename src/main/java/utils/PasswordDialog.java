package utils;

import javax.swing.*;

public class PasswordDialog {

    private PasswordDialog() {}

    public static String prompt() {
        JPasswordField pwd = new JPasswordField(20);
        JOptionPane.showConfirmDialog(null, pwd,"Enter User's Password", JOptionPane.OK_CANCEL_OPTION);
        return new String(pwd.getPassword());
    }
}