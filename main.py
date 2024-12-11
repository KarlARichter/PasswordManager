"""
-------------------------------------------------------
main.py
Password Manager Project
-------------------------------------------------------
Author: Karl Richter
Contact: karlalexrichter@gmail.com    
Github Repo: https://github.com/KarlARichter/PW_MANAGER
Last Updated: 2024-11-29
-------------------------------------------------------
"""

#Testing Use Master Password: 123

from datetime import datetime
from cryptography.fernet import Fernet
from zxcvbn import zxcvbn
import os
import sys
import random
import bcrypt
import string


# Encrypted key generation
def load_key():
    if not os.path.exists("encrypted.key"):
        key = Fernet.generate_key()
        with open("encrypted.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("encrypted.key", "rb") as key_file:
            key = key_file.read()
    return key


# Encrypt a password
def encrypt_password(password, cipher_suite):
    return cipher_suite.encrypt(password.encode())


# Decrypt a password
def decrypt_password(encrypted_password, cipher_suite):
    return cipher_suite.decrypt(encrypted_password).decode()


# Generate a secure password with custom specified length
def generate_secure_password(length=16):
    
    while True:
        characters = string.ascii_letters + string.digits + string.punctuation
        secure_password = ''.join(random.choice(characters) for _ in range(length))

        if (any(c.islower() for c in secure_password) and
            any(c.isupper() for c in secure_password) and
            any(c.isdigit() for c in secure_password) and
            any(c in string.punctuation for c in secure_password)):
            if zxcvbn(secure_password)['score'] >= 3:
                return secure_password


# Add a new password
def add_password(cipher_suite):
    account_name = input("Enter the account name (username): ")

    use_generated = input("Would you like to generate a secure password? (yes/no): ").strip().lower()
    if use_generated == 'yes':
        try:
            length = int(input("Enter the desired password length (minimum 12, maximum 30): "))
            
            # Verify length
            if length < 12 or length > 30:
                print("\nWarning: Password length is out of the recommended range. Generating password with default length (12).")
                password = generate_secure_password(12)  # Generate password regardless of length validity
                print(f"\nGenerated Password: {password}")
            
            # Lenght verified
            else:
                password = generate_secure_password(length)
                print(f"\nGenerated Password: {password}")
                
        except ValueError as e:
            # valid int check
            print(f"\nInvalid length input: {e}. Generating password with default length (12).")
            password = generate_secure_password()
            # use default length
            print(f"\nGenerated Password: {password}")  
    else:
        password = input("Enter the password: ")

    #Prompt user with weak password msg
    score = pw_strength(password)
    if score < 3:
        print("\nThe password is too weak. Please use a stronger password.")
        return     
        
    print("\nPassword Added!")
    encrypted_password = encrypt_password(password, cipher_suite)

    # Store the encrypted password in the file
    with open("passwords.txt", "ab") as file:
        file.write(f"{account_name}:".encode() + encrypted_password + b"\n")

    #AUDIT LOG
    action_log("ADD_PASSWORD", account_name)
          

# Display stored passwords
def view_passwords(cipher_suite):
    # Check if the file exists and is non-empty
    if not os.path.exists("passwords.txt") or os.path.getsize("passwords.txt") == 0:
        print("\nNo passwords stored yet.")
        return

    try:
        with open("passwords.txt", "rb") as file:
            has_passwords = False  
            
            # Calculate the maximum length for account names for alignment
            max_account_name_len = max(len(line.split(b":", 1)[0]) for line in file)
            file.seek(0)  
            
            for line in file:
                account_name, encrypted_password = line.split(b":", 1)
                decrypted_password = decrypt_password(encrypted_password.strip(), cipher_suite)
                
                # Print with aligned columns
                print(f"Account: {account_name.decode().ljust(max_account_name_len)} | Password: {decrypted_password}")
                print("----------------------------------------------------------------")
                has_passwords = True
            
            # Error check for empty txt
            if not has_passwords:
                print("\nNo passwords stored yet.")
    except FileNotFoundError:
        print("\nNo passwords stored yet.")
    
    #AUDIT LOG
    action_log("VIEW_PASSWORDS")


# Delete a stored password
def delete_password(cipher_suite):
    
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

    # No stored passwords
    if not passwords:
        print("\nNo passwords to delete.")
        return

    print("Stored Accounts:")
    for i, (account_name, _) in enumerate(passwords, 1):
        print(f"{i}. {account_name}")

    try:
        # Get user input for which account to delete
        choice = int(input("\nEnter the number of the account to delete: ")) - 1
        if 0 <= choice < len(passwords):
            account_to_delete = passwords[choice][0]
            passwords.pop(choice)

            # Rewrite the file without the deleted account
            with open("passwords.txt", "wb") as file:
                for account_name, password in passwords:
                    encrypted_password = encrypt_password(password, cipher_suite)
                    file.write(f"{account_name}:".encode() + encrypted_password + b"\n")
                
                #AUDIT LOG
                action_log("DELETE_PASSWORD", account_to_delete)
            print(f"\nDeleted account: {account_to_delete}")
        else:
            print("\nInvalid selection.")
    except ValueError:
        print("\nPlease enter a valid number.")


# Create masterpassword
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


# If master password exists
def verify_master_password():
    try:
        with open("master.key", "rb") as f:
            stored_hash = f.read()
        attempts = 3
        while attempts > 0:
            master_password = input("Enter the master password: ")
            if bcrypt.checkpw(master_password.encode(), stored_hash):
                print("\nAccess granted.")
                action_log("LOGIN_SUCCESSFULL")
                return True
            else:
                attempts -= 1
                print(f"Incorrect password. {attempts} attempts left.")
                action_log("LOGIN_FAILURE")
        print("\nAccess denied.")
        action_log("LOGIN_DENIED")
        return False
    except FileNotFoundError:
        print("Master password file not found. Please set up the master password first.")
        action_log("MASTER_PASSWORD_FILE_NOT_FOUND")
        return False


# Change masterpass
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

    #AUDIT LOG
    action_log("CHANGE_MASTER_PASSWORD")


#zxcvbn library implementation
def pw_strength(password):
    strength = zxcvbn(password)
    score = strength['score']
    feedback = strength['feedback']

    print(f"\nPassword Strength: {['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong'][score]}")
    if feedback['warning']:
        print("\n--------------------------------------------------------------")
        print(f"Warning: {feedback['warning']}")
    if feedback['suggestions']:
        print("\nSuggestions:")
        for suggestion in feedback['suggestions']:
            print(f"- {suggestion}")
        print("--------------------------------------------------------------")
    return score


#Action log system
def action_log(action, account_name=None):
    with open("audit.log", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if account_name:
            log_file.write(f"[{timestamp}] ACTION: {action} | ACCOUNT: {account_name}\n")
        else:
            log_file.write(f"[{timestamp}] ACTION: {action}\n")


#Log file size 
def rotate_log_file():
    if os.path.exists("audit.log") and os.path.getsize("audit.log") > 5 * 1024 * 2024:
        os.rename("audit.log", f"audit_{datetime.now().strftime('%Y%m%d%H%M%S')}.log")


#Clear log file
def clear_log():
    confirmation = input("Are you sure you want to clear the audit log? This action cannot be undone. (yes/no): ").strip().lower()
    if confirmation == 'yes':
        with open("audit.log", "w") as log_file:
            log_file.write("")
        print("\nAudit log cleared.")
        action_log("CLEAR_LOG")
    else:
        print("\nClear log action canceled.")


#Prints contents of log file
def view_log(file_path):
    try:
        with open(file_path, "r") as log_file:
            print("\n---- Log File Content ----\n")
            for line in log_file:
                print(line.strip())
            print("\n---- End of Log File ----")
    
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")
    

# Main program ui
def main():
    log_file_path = 'audit.log'
    setup_master_password()
    if verify_master_password():
        key = load_key()
        cipher_suite = Fernet(key)
        while True:
            print("\n---- Password Manager ----")
            print("1. Add a new password")
            print("2. View stored passwords")
            print("3. Delete a password")
            print("4. Change master password")
            print("5. View log file")
            print("6. Clear log file")
            print("7. Exit")
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
                view_log(log_file_path)
            elif choice == '6':
                clear_log()
            elif choice == '7':
                print("\nExiting program.")
                action_log("EXITED_PROGRAM")
                break
            else:
                print("\nInvalid choice. Please try again.")


#Main
if __name__ == "__main__":
    main()
