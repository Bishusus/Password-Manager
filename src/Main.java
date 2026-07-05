import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

/**
 * The main entry point for the password manager.
 * This class handles the command-line interface menu loops, processes what the user types,
 * and passes those requests down to the database and encryption systems.
 */
public class Main {

    /**
     * Starts the application, checks if a master password exists, handles the
     * login/registration phase, and boots up the main CRUD menu loop.
     */
    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);
        PasswordManager manager = new PasswordManager();

        boolean running = true;
        // First-time setup check: If no master account exists, force them to create one
        if (!manager.database.isRegistered()) {
            System.out.println("\n===== Welcome to Password Manager ======\n");
            System.out.println("1. Create master password");
            System.out.println("2. Exit");
            System.out.print("Choice: ");

            int choice = sc.nextInt();
            sc.nextLine();

            switch (choice) {
                case 1:
                    while (true) {
                        System.out.print("Enter a new master password: ");
                        String password = sc.nextLine();
                        System.out.print("Confirm the new master password: ");
                        String confirmPassword = sc.nextLine();
                        if (password.equals(confirmPassword)) {
                            // Generate a fresh key, random salt, and capture the iteration settings
                            EncryptionManager encryption = new EncryptionManager(password);
                            SecretKey secretKey = encryption.getSecretKey();
                            byte[] salt = encryption.getSalt();
                            int iterations = encryption.getIterations();

                            // Turn the raw byte arrays into text so we can save them cleanly in MySQL
                            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
                            String encodedSalt = Base64.getEncoder().encodeToString(salt);

                            manager.database.saveMasterAuth(encodedSalt, encodedKey, iterations);
                            System.out.println("Master password created successfully.");
                            break;
                        } else {
                            System.out.println("Passwords do not match!");
                        }
                    }
                    break;

                case 2:
                    manager.database.close();
                    System.out.println("Goodbye!");
                    return;

                default:
                    System.out.println("Wrong choice!");
                    return;
            }
        }

        EncryptionManager encryption;

        // Login Loop: Keeps asking for the master password until it matches
        while (true) {
            System.out.println("\n===== Welcome to Password Manager =====\n");
            System.out.print("Enter the master password: ");
            String master_password = sc.nextLine();
            MasterAuth master = manager.database.loadMasterAuth();
            byte[] decodedSalt = Base64.getDecoder().decode(master.salt());
            String encodedKey = master.verifier();

            // Re-derive the key using the password they just typed and the salt we saved earlier
            encryption = new EncryptionManager(master_password, decodedSalt);
            SecretKey secretKey = encryption.getSecretKey();
            String encodedKey2 = Base64.getEncoder().encodeToString(secretKey.getEncoded());

            // If the newly generated key matches the one on file, they are authenticated
            if (encodedKey.equals(encodedKey2)) {
                manager.setEncryptionManager(encryption);
                break;
            } else {
                System.out.println("Incorrect password! Please try again!");
            }
        }

        // Core App Loop: Handles the actual CRUD interactions once logged in
        while (running) {

            System.out.println("\n===== Password Manager =====\n");
            System.out.println("1. Add Entry");
            System.out.println("2. View All Entries");
            System.out.println("3. Find Entry");
            System.out.println("4. Edit Entry");
            System.out.println("5. Delete Entry");
            System.out.println("6. Exit");
            System.out.print("Choice: ");

            int choice = sc.nextInt();
            sc.nextLine();

            switch (choice) {

                case 1:
                    System.out.print("Topic: ");
                    String topic = sc.nextLine();

                    System.out.print("Username: ");
                    String username = sc.nextLine();

                    System.out.print("Password: ");
                    String password = sc.nextLine();

                    manager.addEntry(topic, username, password);
                    break;

                case 2:
                    List<PasswordEntry> entries = manager.database.findAll();
                    System.out.println("All Entries:");
                    System.out.println("--------------");
                    System.out.println();
                    if (!entries.isEmpty()) {
                        for (PasswordEntry entry : entries) {
                            // Pull the encrypted password and its unique IV, decrypt it on the fly to display it
                            String decryptedPassword = encryption.decrypt(entry.getPassword(), entry.getIv());
                            System.out.println("Topic: " + entry.getTopic() + "\n" +
                                    "Username: " + entry.getUsername() + "\n"
                                    + "Password: " + decryptedPassword);
                            System.out.println();
                        }
                    } else {
                        System.out.println("No entries found");
                    }
                    break;

                case 3:
                    System.out.print("Enter topic: ");
                    topic = sc.nextLine();

                    PasswordEntry entry = manager.findEntry(topic);

                    if (entry != null) {
                        String decryptedPassword = encryption.decrypt(entry.getPassword(), entry.getIv());
                        System.out.println("Topic: " + entry.getTopic() + "\n" +
                                "Username: " + entry.getUsername() + "\n" +
                                "Password: " + decryptedPassword);
                    } else {
                        System.out.println("Entry not found.");
                    }

                    break;

                case 4:
                    System.out.print("Enter topic: ");
                    topic = sc.nextLine();

                    manager.editEntry(topic);
                    break;

                case 5:
                    System.out.print("Enter topic: ");
                    topic = sc.nextLine();

                    manager.deleteEntry(topic);
                    break;

                case 6:
                    running = false;
                    manager.database.close();
                    System.out.println("Goodbye!");
                    break;

                default:
                    System.out.println("Invalid choice.");
            }
        }
        sc.close();
    }
}