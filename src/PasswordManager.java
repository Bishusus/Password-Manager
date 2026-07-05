import java.util.Scanner;

/**
 * The middle coordinator class. Tries to match console interactions from Main
 * down to database commands and execution tasks.
 */
public class PasswordManager {
    public DatabaseSQL database;
    Scanner sc;
    private EncryptionManager encryption;

    /**
     * Hooks up a database instance and sets up a standard input reader.
     */
    public PasswordManager() {
        database = new DatabaseSQL();
        sc = new Scanner(System.in);
    }

    /**
     * Attaches the authenticated encryption instance to the manager layer.
     */
    public void setEncryptionManager(EncryptionManager encryption) {
        this.encryption = encryption;
    }

    /**
     * Normalizes the topic tag, encrypts the password, and inserts the fresh row to the database.
     */
    public void addEntry (String topic, String username, String password) {
        topic = topic.toLowerCase(); // Forces everything lowercase so lookups aren't case-sensitive
        EncryptedPassword password1 = encryption.encrypt(password);
        String iv = password1.iv();
        PasswordEntry entry = new PasswordEntry(topic, username, password1.encryptedPassword(), iv);
        if (database.findByTitle(topic) == null)
        {
            database.insert(entry);
        }
        else {
            System.out.println("Entry already exists");
        }

    }

    /**
     * Finds a single password row matching a given topic.
     */
    public PasswordEntry findEntry(String topic) { return database.findByTitle(topic.toLowerCase()); }

    /**
     * Manages the text menus when editing fields (topic name, username, or raw password values).
     */
    public void editEntry(String topic) {
        PasswordEntry entry = findEntry(topic);
        if (entry != null) {
            System.out.println("Entry found.");
            System.out.println("What would you like to edit?");
            System.out.println();
            System.out.println("""
                    1. Topic
                    2. Username
                    3. Password
                    4. Cancel
                    """);
            System.out.print("Choice(Type 1, 2, 3 and 4 accordingly): ");
            int choice = sc.nextInt();
            sc.nextLine();
            switch (choice) {
                case 1 :
                    System.out.print("Enter your new topic name: ");
                    String newTopic = sc.nextLine().toLowerCase();
                    entry.setTopic(newTopic);
                    System.out.println("Topic updated successfully.");
                    break;
                case 2:
                    System.out.print("Enter your new username: ");
                    String newUsername = sc.nextLine();
                    entry.setUsername(newUsername);
                    System.out.println("Username updated successfully.");
                    break;
                case 3:
                    System.out.print("Enter your new password: ");
                    String newPassword = sc.nextLine();
                    // Encrypt the brand new password securely and grab a new IV tracking value along with it
                    EncryptedPassword password1 = encryption.encrypt(newPassword);
                    entry.setPassword(password1.encryptedPassword());
                    entry.setIv(password1.iv());
                    System.out.println("Password updated successfully.");
                    break;
                case 4:
                    System.out.println("Cancelled");
                    return;
                default:
                    System.out.println("Invalid choice.");
                    return;
            }
            database.update(topic, entry, choice);
        }
        else {
            System.out.println("Entry not found");
        }
    }

    /**
     * Asks for confirmation before wiping out an entry row from the database.
     */
    public void deleteEntry(String topic) {
        PasswordEntry entry = findEntry(topic);
        if (entry != null) {
            System.out.println("Entry found.");
            System.out.print("Are you sure you want to delete the entry?(Type yes or no): ");
            String confirmation = sc.nextLine().toLowerCase();
            if (confirmation.equals("yes")) {
                database.delete(entry);
            }
            else if  (confirmation.equals("no")) {
                System.out.println("Deletion cancelled.");
            }
            else System.out.println("Invalid choice.");
        }
    }
}