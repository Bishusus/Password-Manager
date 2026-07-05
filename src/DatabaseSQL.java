import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class DatabaseSQL {

    private final Connection connection;
    private static final String url = "jdbc:mysql://localhost:3306/encrypted_passwords";
    private static final String username = "root";
    private static final String password = "";

    public DatabaseSQL() {
        try {
            connection = DriverManager.getConnection(url, username, password);
            Statement myStatement = connection.createStatement();
            String sql = """
                CREATE TABLE IF NOT EXISTS passwords (
                id INT PRIMARY KEY AUTO_INCREMENT,
                topic VARCHAR(100) UNIQUE,
                username VARCHAR(100),
                password VARCHAR(255),
                iv VARCHAR(255)
            )
            """;
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

    public void close() {
        try {
            connection.close();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
