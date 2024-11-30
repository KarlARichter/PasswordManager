Python password manager using AES-256 encryption with the cryptography library and bcrypt for secure storage and master password management. Features include:

1. Master Password System: Utilizes hashed and salted verification for secure authentication with an option to change the master password.

2. Custom Password Generation: Supports generation of strong passwords with length validation and security checks using the zxcvbn library for strength analysis and feedback.

3. Password Encryption/Decryption: Safely encrypts and decrypts passwords for storage and retrieval.

4. CRUD Operations: Allows users to create, view, update, and delete encrypted passwords associated with account names.

5. Audit Logging: Tracks user actions (e.g., adding, viewing, deleting passwords, login attempts) in a timestamped audit.log file for accountability.

6. Log Management: Includes features to clear the audit log and rotate log files when they exceed a size threshold for efficient storage management.

7. Password Strength Validation: Rejects weak passwords based on a minimum threshold for strength, providing warnings and actionable feedback for improvement.

8. Secure Access Controls: Tracks login success, failures, and access denial attempts to ensure secure usage.