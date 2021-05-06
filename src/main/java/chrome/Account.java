package chrome;

public class Account {

    public String originUrl;
    public String usernameValue;
    public String passwordValue;

    public String dateCreated;
    public Integer timesUsed;
    public Boolean blacklisted;

    public String toString(boolean verbose) {
        StringBuilder sb = new StringBuilder();
        sb.append(originUrl).append('\n');

        if (usernameValue != null) sb.append("username: ").append(usernameValue).append("\n");
        if (passwordValue != null) sb.append("password: ").append(passwordValue).append("\n");

        if (verbose) {
            if (dateCreated != null) sb.append("date_created: ").append(dateCreated).append('\n');
            if (timesUsed != null) sb.append("times_used: ").append(timesUsed).append('\n');
            if (blacklisted != null) sb.append("blacklisted: ").append(blacklisted).append('\n');
        }

        return sb.toString();
    }

    @Override
    public String toString() {
        return toString(false);
    }
}
