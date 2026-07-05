import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Handles all application security systems.
 * Uses PBKDF2 to convert weak string passwords into strong cryptographic keys,
 * and utilizes AES-GCM to securely encrypt and decrypt actual credential text blocks.
 */
public class EncryptionManager {
    private final SecretKey secretKey;
    private final int iterations = 100000;
    private final byte[] salt;

    /**
     * Constructor used during initial app setup. Generates a brand-new random salt
     * and derives the master key.
     */
    public EncryptionManager(String masterPassword) {
        salt = generateSalt();
        this.secretKey = masterKey(masterPassword, salt);
    }

    /**
     * Constructor used for normal logins. Takes the existing salt out of the database
     * to rebuild the master session key.
     */
    public EncryptionManager(String masterPassword, byte[] salt) {
        this.secretKey = masterKey(masterPassword, salt);
        this.salt = salt;
    }

    /**
     * Uses PBKDF2WithHmacSHA256 to stretch a regular text password into a secure 256-bit AES key.
     */
    public SecretKey masterKey(String masterPassword, byte[] salt) {
        char[] password = masterPassword.toCharArray();

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

            byte[] keyBytes = skf.generateSecret(spec).getEncoded();

            return new SecretKeySpec(keyBytes, "AES");

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } finally {
            spec.clearPassword(); // Wipe the character array immediately to secure memory space
        }
    }

    /**
     * Encrypts a clean string using AES/GCM/NoPadding. Generates a fresh 12-byte IV for every task.
     *
     * @return a container holding both the encrypted text block and its matching IV string.
     */
    public EncryptedPassword encrypt(String plainText) {
        try {
            Cipher cipher =  Cipher.getInstance("AES/GCM/NoPadding");
            byte[] iv = new byte[12];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
            byte[] cipherText = cipher.doFinal(plainTextBytes);
            String encryptedPassword = Base64.getEncoder().encodeToString(cipherText);
            String ivString = Base64.getEncoder().encodeToString(iv);
            return new EncryptedPassword(encryptedPassword, ivString);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Reverses encrypted text strings back into standard readable text using the active key.
     */
    public String decrypt(String encryptedPassword, String iv) {
        byte[] decodedPassword = Base64.getDecoder().decode(encryptedPassword);
        byte[] decodedIv = Base64.getDecoder().decode(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, decodedIv);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            byte[] plainTextBytes = cipher.doFinal(decodedPassword);
            return new String(plainTextBytes, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates a unique random 16-byte salt sequence.
     */
    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        return salt;
    }

    public int getIterations() {
        return iterations;
    }

    public byte[] getSalt() {
        return salt;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }
}