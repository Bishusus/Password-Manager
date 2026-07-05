# Secure Password Manager

A command-line password manager built in Java that securely stores and manages account credentials using modern cryptographic techniques. Passwords are encrypted before being stored in a MySQL database, ensuring that sensitive information is never saved in plaintext.

## Features

* Secure user authentication using a master password
* AES-GCM encryption for confidential and authenticated password storage
* PBKDF2-HMAC-SHA256 key derivation from the master password
* Random IV generation for every encrypted password
* MySQL database for persistent credential storage
* Add new password entries
* Search for stored credentials by topic
* View all saved credentials
* Update existing entries
* Delete stored entries
* Case-insensitive topic searching

## Technologies Used

* Java
* MySQL
* JDBC
* AES/GCM/NoPadding
* PBKDF2WithHmacSHA256
* Base64 Encoding

## Security

This project follows several security best practices:

* Passwords are encrypted using **AES-GCM**, which provides both confidentiality and integrity.
* The encryption key is **never stored** in the database.
* The encryption key is derived from the master password using **PBKDF2WithHmacSHA256**.
* A unique random Initialization Vector (IV) is generated for every encryption operation.
* Encrypted passwords and IVs are stored in Base64 format for database compatibility.

## Database Schema

### passwords

| Column   | Description                               |
| -------- | ----------------------------------------- |
| id       | Unique identifier                         |
| topic    | Website or service name                   |
| username | Account username                          |
| password | AES-GCM encrypted password                |
| iv       | Initialization Vector used for encryption |

## Getting Started

### Prerequisites

* Java JDK 17 or later
* MySQL Server
* MySQL Connector/J (JDBC Driver)

### Installation

1. Clone the repository.

```bash
git clone <repository-url>
```

2. Create the database.

```sql
CREATE DATABASE encrypted_passwords;
```

3. Update the database connection information inside `DatabaseSQL.java`.

```java
private static final String url = "jdbc:mysql://localhost:3306/encrypted_passwords";
private static final String username = "root";
private static final String password = "";
```

Replace these values with your own MySQL credentials.

4. Add the MySQL JDBC driver to your project.

5. Compile and run the application.

## Usage

After launching the application, you can:

* Create or authenticate with your master password.
* Add new password entries.
* Retrieve stored credentials.
* Update existing entries.
* Delete entries when no longer needed.
* View all saved credentials.

## Project Structure

```text
src/
├── Main.java
├── PasswordManager.java
├── DatabaseSQL.java
├── PasswordEntry.java
├── EncryptionManager.java
├── EncryptedPassword.java
└── ...
```

## Future Improvements

* Password strength analysis
* Password generator
* Import and export functionality
* Automatic database backups
* Password categories
* Secure clipboard copying
* Graphical user interface (GUI)
* Vault reset option for forgotten master passwords
* Search by username
* Secure password masking while typing

## Notes

This project is intended for educational purposes and demonstrates the implementation of secure password storage using modern cryptographic practices in Java.

If the master password is forgotten, the encrypted passwords cannot be recovered because the encryption key is derived from the master password. This behavior is intentional and reflects the design of secure password managers.

## License

This project is open source and available under the MIT License.
