"""
-------------------------------------------------------
Main.py
Password Manager/Generator Project
-------------------------------------------------------
Author: Karl Richter    
Github: https://github.com/KarlARichter/PW_MANAGER
Last Updated: 2024-11-15
-------------------------------------------------------
"""

#Current Master Password: 12345

from cryptography.fernet import Fernet
import os
import random
import bcrypt
import string

# Generate or load the encryption key
def load_key():
    # If the key file does not exist, create it
    if not os.path.exists("encrypted.key"):
        key = Fernet.generate_key()
        with open("encrypted.key", "wb") as key_file:
            key_file.write(key)
    else:
        # Load the existing key
        with open("encrypted.key", "rb") as key_file:
            key = key_file.read()
    return key


# Encrypt a password
def encrypt_password(password, cipher_suite):
    return cipher_suite.encrypt(password.encode())


# Decrypt a password
def decrypt_password(encrypted_password, cipher_suite):
    return cipher_suite.decrypt(encrypted_password).decode()


# Generate a secure password with user-specified length
def generate_secure_password(length=16):
    # Ensures the password includes a mix of uppercase, lowercase, digits, and special characters
        
    characters = string.ascii_letters + string.digits + string.punctuation
    secure_password = ''.join(random.choice(characters) for _ in range(length))

    # Ensure the generated password contains at least one of each character type
    if (any(c.islower() for c in secure_password) and
        any(c.isupper() for c in secure_password) and
        any(c.isdigit() for c in secure_password) and
        any(c in string.punctuation for c in secure_password)):
        return secure_password
    else:
        # If criteria not met, recursively call to generate a new one
        return generate_secure_password(length)

# Add a new password
def add_password(cipher_suite):
    account_name = input("Enter the account name (username): ")

    use_generated = input("Would you like to generate a secure password? (yes/no): ").strip().lower()
    if use_generated == 'yes':
        try:
            length = int(input("Enter the desired password length (minimum 12, maximum 30): "))
            # Check if the length is within the valid range
            if length < 12 or length > 30:
                print("\nWarning: Password length is out of the recommended range. Generating password with default length (12).")
                password = generate_secure_password(12)  # Generate password regardless of length validity
                print(f"\nGenerated Password: {password}")
            
            #if in valid range 
            else:
                password = generate_secure_password(length)
                print(f"\nGenerated Password: {password}")
                
        except ValueError as e:
            # If the input is not a valid integer, use the default length
            print(f"\nInvalid length input: {e}. Generating password with default length (12).")
            password = generate_secure_password()
            print(f"\nGenerated Password: {password}")  # Default length
    else:
        password = input("Enter the password: ")
        print("\nPassword Added!")
        

    encrypted_password = encrypt_password(password, cipher_suite)

    # Store the encrypted password in the file
    with open("passwords.txt", "ab") as file:
        file.write(f"{account_name}:".encode() + encrypted_password + b"\n")

          
# Display all stored passwords
def view_passwords(cipher_suite):
    # Check if the file exists and is non-empty
    if not os.path.exists("passwords.txt") or os.path.getsize("passwords.txt") == 0:
        print("\nNo passwords stored yet.")
        return

    try:
        with open("passwords.txt", "rb") as file:
            has_passwords = False  # Track if any passwords are found
            
            # Calculate the maximum length for account names for alignment
            max_account_name_len = max(len(line.split(b":", 1)[0]) for line in file)
            file.seek(0)  # Reset file pointer to the beginning
            
            for line in file:
                account_name, encrypted_password = line.split(b":", 1)
                decrypted_password = decrypt_password(encrypted_password.strip(), cipher_suite)
                
                # Print with aligned columns
                print(f"Account: {account_name.decode().ljust(max_account_name_len)} | Password: {decrypted_password}")
                print("----------------------------------------------------------------")
                has_passwords = True
            
            # Check if no passwords were found
            if not has_passwords:
                print("\nNo passwords stored yet.")
    except FileNotFoundError:
        print("\nNo passwords stored yet.")


# Delete a stored password
def delete_password(cipher_suite):
    # Load all passwords
    passwords = []
    try:
        with open("passwords.txt", "rb") as file:
            for line in file:
                account_name, encrypted_password = line.split(b":", 1)
                decrypted_password = decrypt_password(encrypted_password.strip(), cipher_suite)
                passwords.append((account_name.decode(), decrypted_password))
    except FileNotFoundError:
        print("\nNo passwords stored yet.")
        return

    # Display passwords for selection
    if not passwords:
        print("\nNo passwords to delete.")
        return

    print("Stored Accounts:")
    for i, (account_name, _) in enumerate(passwords, 1):
        print(f"{i}. {account_name}")

    try:
        # Get user input for which account to delete
        choice = int(input("Enter the number of the account to delete: ")) - 1
        if 0 <= choice < len(passwords):
            account_to_delete = passwords[choice][0]
            passwords.pop(choice)

            # Rewrite the file without the deleted account
            with open("passwords.txt", "wb") as file:
                for account_name, password in passwords:
                    encrypted_password = encrypt_password(password, cipher_suite)
                    file.write(f"{account_name}:".encode() + encrypted_password + b"\n")

            print(f"\nDeleted account: {account_to_delete}")
        else:
            print("\nInvalid selection.")
    except ValueError:
        print("\nPlease enter a valid number.")


def setup_master_password():
    if not os.path.exists("master.key"):
        master_password = input("Set a master password: ")
        # Hash the master password with a salt
        hashed_master = bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())
        with open("master.key", "wb") as f:
            f.write(hashed_master)
        print("Master password has been set.")
    else:
        print("Master password is already set.")


# Function to verify the master password on program start
def verify_master_password():
    try:
        with open("master.key", "rb") as f:
            stored_hash = f.read()
        attempts = 3
        while attempts > 0:
            master_password = input("Enter the master password: ")
            if bcrypt.checkpw(master_password.encode(), stored_hash):
                print("\nAccess granted.")
                return True
            else:
                attempts -= 1
                print(f"Incorrect password. {attempts} attempts left.")
        print("\nAccess denied.")
        return False
    except FileNotFoundError:
        print("Master password file not found. Please set up the master password first.")
        return False


def change_master_password():
    try:
        with open("master.key", "rb") as f:
            stored_hash = f.read()
        
        # Verify the current master password
        current_password = input("\nEnter the current master password: ")
        if bcrypt.checkpw(current_password.encode(), stored_hash):
            # Prompt for the new master password
            new_password = input("Enter the new master password: ")
            confirm_password = input("Confirm the new master password: ")
            if new_password == confirm_password:
                new_hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
                with open("master.key", "wb") as f:
                    f.write(new_hashed)
                print("\nMaster password has been successfully changed.")
            else:
                print("\nNew passwords do not match. Master password not changed.")
        else:
            print("\nIncorrect current master password. Master password not changed.")
    except FileNotFoundError:
        print("Master password file not found. Please set up the master password first.")


# Main program
def main():
    setup_master_password()
    if verify_master_password():
        key = load_key()
        cipher_suite = Fernet(key)
        while True:
            print("\n--- Password Manager ---")
            print("1. Add a new password")
            print("2. View stored passwords")
            print("3. Delete a password")
            print("4. Change master password")
            print("5. Exit Program")
            choice = input("\nChoose an option: ")
            if choice == '1':
                add_password(cipher_suite)
            elif choice == '2':
                print()
                print("----------------------------------------------------------------")
                view_passwords(cipher_suite)
            elif choice == '3':
                delete_password(cipher_suite)
            elif choice == '4':
                change_master_password()
            elif choice == '5':
                print("\nExiting program.")
                break
            else:
                print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
