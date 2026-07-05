/**
 * A record data container designed to bundle together the encrypted
 * password string and its unique IV tracking element.
 */
public record EncryptedPassword(String encryptedPassword, String iv) {

}