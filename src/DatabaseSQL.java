import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles all raw SQL queries and connections to the MySQL database.
 * Uses PreparedStatements to protect against SQL Injection attacks.
 */
public class DatabaseSQL {

    private final Connection connection;
    private static final String url = "jdbc:mysql://localhost:3306/encrypted_passwords";
    private static final String username = "root";
    private static final String password = "";

    /**
     * Connects to the local database and builds the required tables if they don't exist yet.
     */
    public DatabaseSQL() {
        try {
            connection = DriverManager.getConnection(url, username, password);
            Statement myStatement = connection.createStatement();

            // Table for storing usernames and encrypted passwords
            String sql = """
                CREATE TABLE IF NOT EXISTS passwords (
                id INT PRIMARY KEY AUTO_INCREMENT,
                topic VARCHAR(100) UNIQUE,
                username VARCHAR(100),
                password VARCHAR(255),
                iv VARCHAR(255)
            )
            """;

            // Table for storing master login configurations
            String sql2 = """ 
                CREATE TABLE IF NOT EXISTS master_auth (
                id INT PRIMARY KEY AUTO_INCREMENT,
                salt VARCHAR(24),
                encoded VARCHAR(255),
                iterations INT
            )
            """;

            myStatement.execute(sql);
            myStatement.execute(sql2);
            myStatement.close();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Saves a new username/password record to the database.
     */
    public void insert(PasswordEntry entry) {
        String topic = entry.getTopic();
        String username = entry.getUsername();
        String password = entry.getPassword();
        String iv = entry.getIv();
        String sql = """
                INSERT INTO passwords (topic , username, password, iv) VALUES (?, ?, ?, ?)
                """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, topic);
            ps.setString(2, username);
            ps.setString(3, password);
            ps.setString(4, iv);
            int rows = ps.executeUpdate();
            if (rows > 0) {
                System.out.println("Entry inserted successfully.");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Searches for a single account entry using its topic name.
     *
     * @return a filled PasswordEntry object if found, otherwise returns null.
     */
    public PasswordEntry findByTitle(String topic) {
        String sql = """
                SELECT * FROM passwords WHERE topic = ?
        """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, topic);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return new PasswordEntry(rs.getString("topic"), rs.getString("username"), rs.getString("password"), rs.getString("iv"));
            }
            else {
                return null;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Updates an existing entry depending on what the user wants to change.
     * Choice 1 = updates topic name, Choice 2 = updates username, Choice 3 = updates password + IV.
     */
    public void update(String topic, PasswordEntry entry, int choice) {
        int rows = 0;
        if (choice == 1) {
            String sql = """
                    UPDATE passwords SET topic = ? WHERE topic = ?
                    """;

            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, entry.getTopic());
                ps.setString(2, topic);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }
        else if (choice == 2) {
            String sql = """
                    UPDATE passwords SET username = ? WHERE topic = ?
                    """;
            try (PreparedStatement ps = connection.prepareStatement(sql)){
                ps.setString(1, entry.getUsername());
                ps.setString(2, topic);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }
        else if (choice == 3) {
            String sql = """
                    UPDATE passwords SET password = ?, iv = ? WHERE topic = ?
                    """;
            try (PreparedStatement ps = connection.prepareStatement(sql)){
                ps.setString(1, entry.getPassword());
                ps.setString(2, entry.getIv());
                ps.setString(3, topic);
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Pulls every stored password row from the database and compiles them into a list.
     */
    public List<PasswordEntry> findAll() {
        List<PasswordEntry> entries = new ArrayList<>();
        String sql = """
                SELECT * FROM passwords
        """;
        try(PreparedStatement ps = connection.prepareStatement(sql)){
            ResultSet rs = ps.executeQuery();
            while (rs.next()) {
                entries.add(new PasswordEntry(rs.getString("topic"), rs.getString("username"), rs.getString("password"), rs.getString("iv")));
            }
            return entries;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Completely deletes a saved credential entry matching the selected topic.
     */
    public void delete(PasswordEntry entry) {
        String sql = """
                DELETE FROM passwords WHERE topic = ?
                """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1,  entry.getTopic());
            int rows = ps.executeUpdate();
            if (rows > 0) System.out.println("Entry deleted successfully.");
            else  System.out.println("No matching entry found.");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Checks if a master password has already been registered in the database.
     */
    public boolean isRegistered() {
        String sql = """
                SELECT * FROM master_auth
                """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return true;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    /**
     * Saves the master login credentials (salt, verifier key, and iteration count) to database.
     */
    public void saveMasterAuth(String salt, String encoded, int iterations) {
        String sql = """
                INSERT INTO master_auth (salt , encoded, iterations) VALUES (?, ?, ?)""";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, salt);
            ps.setString(2, encoded);
            ps.setInt(3, iterations);
            int rows = ps.executeUpdate();
            if (rows > 0) System.out.println("Entry saved successfully.");
            else System.out.println("No matching entry found.");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Loads the master password record for login validation.
     */
    public MasterAuth loadMasterAuth() {
        String sql = """
                SELECT * FROM master_auth
                """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                String salt = rs.getString("salt");
                String encoded = rs.getString("encoded");
                int iterations = rs.getInt("iterations");
                return new MasterAuth(salt, encoded, iterations);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    /**
     * Safely closes the active database connection connection.
     */
    public void close() {
        try {
            connection.close();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}