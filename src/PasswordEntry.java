/**
 * A standard data object that models a single password entry row from the database.
 */
public class PasswordEntry {

    private String topic;
    private String username;
    private String password;
    private String iv;

    /**
     * Creates a structured entry containing the site topic, username, encrypted password, and cipher IV.
     */
    public PasswordEntry(String topic, String username, String password, String iv) {
        this.topic = topic;
        this.username = username;
        this.password =password;
        this.iv = iv;
    }

    public String getTopic() {
        return topic;
    }

    public void setTopic(String topic) {
        this.topic = topic;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    @Override
    public String toString() {
        return "Topic: " + topic + "\n" +
                "Username: " + username + "\n" +
                "Password: " + password + "\n" +
                "IV: " + iv;
    }
}