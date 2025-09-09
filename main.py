import json
import os
import re
import hashlib
from typing import Dict, Optional, Tuple

class UserManager:
    """Handles user registration, login, and account management"""
    
    def __init__(self, users_file: str = "users.json"):
        self.users_file = users_file
        self.users = self.load_users()
        self.max_login_attempts = 3
    
    def load_users(self) -> Dict:
        """Load users from JSON file"""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                return {}
        return {}
    
    def save_users(self):
        """Save users to JSON file"""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def validate_username(self, username: str) -> bool:
        """Validate username requirements (minimum 6 characters)"""
        return len(username) >= 6
    
    def validate_password(self, password: str) -> bool:
        """Validate password requirements"""
        if len(password) < 8:
            return False
        
        # Check for at least one letter, one number, and one special character
        has_letter = bool(re.search(r'[a-zA-Z]', password))
        has_number = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        return has_letter and has_number and has_special
    
    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Register a new user"""
        # Check if username already exists
        if username in self.users:
            return False, "Username already exists!"
        
        # Validate username
        if not self.validate_username(username):
            return False, "Username must be at least 6 characters long!"
        
        # Validate password
        if not self.validate_password(password):
            return False, "Password must be at least 8 characters long and contain letters, numbers, and special characters!"
        
        # Create user account
        self.users[username] = {
            'password': self.hash_password(password),
            'failed_attempts': 0,
            'blocked': False
        }
        
        self.save_users()
        return True, "Registration successful!"
    
    def login_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Login user with attempt tracking"""
        if username not in self.users:
            return False, "Username not found!"
        
        user = self.users[username]
        
        # Check if account is blocked
        if user['blocked']:
            return False, "Account is blocked due to too many failed attempts!"
        
        # Check password
        if user['password'] == self.hash_password(password):
            # Reset failed attempts on successful login
            user['failed_attempts'] = 0
            self.save_users()
            return True, "Login successful!"
        else:
            # Increment failed attempts
            user['failed_attempts'] += 1
            
            # Block account if max attempts reached
            if user['failed_attempts'] >= self.max_login_attempts:
                user['blocked'] = True
                self.save_users()
                return False, f"Account blocked after {self.max_login_attempts} failed attempts!"
            
            remaining_attempts = self.max_login_attempts - user['failed_attempts']
            self.save_users()
            return False, f"Incorrect password! {remaining_attempts} attempts remaining."


class CipherModule:
    """Implements Atbash, Caesar, and Vigenère ciphers"""
    
    @staticmethod
    def atbash_cipher(text: str, decrypt: bool = False) -> str:
        """
        Atbash cipher: A=Z, B=Y, C=X, etc.
        Since it's symmetric, encryption and decryption are the same operation
        """
        result = ""
        for char in text:
            if char.isalpha():
                if char.isupper():
                    # A=0, Z=25, so A maps to Z (25), B maps to Y (24), etc.
                    result += chr(ord('Z') - (ord(char) - ord('A')))
                else:
                    # a=0, z=25, so a maps to z (25), b maps to y (24), etc.
                    result += chr(ord('z') - (ord(char) - ord('a')))
            else:
                result += char
        return result
    
    @staticmethod
    def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
        """
        Caesar cipher with configurable shift
        """
        if decrypt:
            shift = -shift
        
        result = ""
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                result += char
        return result
    
    @staticmethod
    def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
        """
        Vigenère cipher with keyword
        """
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                # Get the shift value from the key
                shift = ord(key[key_index % len(key)]) - ord('A')
                if decrypt:
                    shift = -shift
                
                if char.isupper():
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                
                key_index += 1
            else:
                result += char
        
        return result


class CipherApp:
    """Main application class"""
    
    def __init__(self):
        self.user_manager = UserManager()
        self.cipher_module = CipherModule()
        self.current_user = None
    
    def display_banner(self):
        """Display application banner"""
        print("=" * 60)
        print("           CIPHER ENCRYPTION/DECRYPTION SYSTEM")
        print("=" * 60)
        print()
    
    def display_main_menu(self):
        """Display main menu options"""
        print("\n--- MAIN MENU ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        print("-" * 20)
    
    def display_cipher_menu(self):
        """Display cipher selection menu"""
        print(f"\n--- WELCOME, {self.current_user}! ---")
        print("Choose a cipher:")
        print("1. Atbash Cipher")
        print("2. Caesar Cipher")
        print("3. Vigenère Cipher")
        print("4. Logout")
        print("-" * 30)
    
    def display_operation_menu(self):
        """Display encryption/decryption menu"""
        print("\nChoose operation:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Back to cipher menu")
        print("-" * 25)
    
    def register_flow(self):
        """Handle user registration"""
        print("\n--- USER REGISTRATION ---")
        username = input("Enter username (min 6 characters): ").strip()
        password = input("Enter password (min 8 chars, letters+numbers+special): ").strip()
        
        success, message = self.user_manager.register_user(username, password)
        print(f"\n{message}")
        
        if success:
            print("You can now login with your credentials.")
    
    def login_flow(self):
        """Handle user login"""
        print("\n--- USER LOGIN ---")
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        success, message = self.user_manager.login_user(username, password)
        print(f"\n{message}")
        
        if success:
            self.current_user = username
            return True
        return False
    
    def atbash_flow(self):
        """Handle Atbash cipher operations"""
        print("\n--- ATBASH CIPHER ---")
        print("Note: Atbash cipher is symmetric (encryption = decryption)")
        
        while True:
            print("\n1. Process text")
            print("2. Back to cipher menu")
            
            choice = input("\nEnter your choice (1-2): ").strip()
            
            if choice == '1':
                text = input("Enter text to process: ")
                result = self.cipher_module.atbash_cipher(text)
                print(f"\nResult: {result}")
            elif choice == '2':
                break
            else:
                print("Invalid choice! Please try again.")
    
    def caesar_flow(self):
        """Handle Caesar cipher operations"""
        print("\n--- CAESAR CIPHER ---")
        
        while True:
            self.display_operation_menu()
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice in ['1', '2']:
                text = input("Enter text: ")
                try:
                    shift = int(input("Enter shift value (1-25): "))
                    if not (1 <= shift <= 25):
                        print("Shift must be between 1 and 25!")
                        continue
                except ValueError:
                    print("Please enter a valid number!")
                    continue
                
                decrypt = (choice == '2')
                result = self.cipher_module.caesar_cipher(text, shift, decrypt)
                operation = "Decrypted" if decrypt else "Encrypted"
                print(f"\n{operation} text: {result}")
                
            elif choice == '3':
                break
            else:
                print("Invalid choice! Please try again.")
    
    def vigenere_flow(self):
        """Handle Vigenère cipher operations"""
        print("\n--- VIGENÈRE CIPHER ---")
        
        while True:
            self.display_operation_menu()
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice in ['1', '2']:
                text = input("Enter text: ")
                key = input("Enter keyword (letters only): ").strip()
                
                if not key.isalpha():
                    print("Keyword must contain only letters!")
                    continue
                
                decrypt = (choice == '2')
                result = self.cipher_module.vigenere_cipher(text, key, decrypt)
                operation = "Decrypted" if decrypt else "Encrypted"
                print(f"\n{operation} text: {result}")
                
            elif choice == '3':
                break
            else:
                print("Invalid choice! Please try again.")
    
    def cipher_selection_flow(self):
        """Handle cipher selection and operations"""
        while True:
            self.display_cipher_menu()
            choice = input("\nEnter your choice (1-4): ").strip()
            
            if choice == '1':
                self.atbash_flow()
            elif choice == '2':
                self.caesar_flow()
            elif choice == '3':
                self.vigenere_flow()
            elif choice == '4':
                print(f"\nGoodbye, {self.current_user}!")
                self.current_user = None
                break
            else:
                print("Invalid choice! Please try again.")
    
    def run(self):
        """Main application loop"""
        self.display_banner()
        
        while True:
            if self.current_user:
                # User is logged in, show cipher menu
                self.cipher_selection_flow()
            else:
                # User not logged in, show main menu
                self.display_main_menu()
                choice = input("Enter your choice (1-3): ").strip()
                
                if choice == '1':
                    self.register_flow()
                elif choice == '2':
                    if self.login_flow():
                        continue  # Successfully logged in, will show cipher menu
                elif choice == '3':
                    print("\nThank you for using the Cipher System!")
                    break
                else:
                    print("Invalid choice! Please try again.")


if __name__ == "__main__":
    app = CipherApp()
    app.run()
