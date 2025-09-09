# Cipher Encryption/Decryption System

A comprehensive console-based application that implements three classic encryption ciphers with secure user authentication.

## Features

### 🔐 User Authentication System
- **Secure Registration**: Username (min 6 chars) and password validation (min 8 chars with letters, numbers, special characters)
- **Login Security**: Account lockout after 3 failed login attempts
- **Password Protection**: SHA-256 hashing for secure password storage
- **Data Persistence**: User accounts saved to JSON file

### 🔒 Cipher Implementations
1. **Atbash Cipher**: Symmetric substitution cipher (A↔Z, B↔Y, etc.)
2. **Caesar Cipher**: Classic shift cipher with configurable shift value (1-25)
3. **Vigenère Cipher**: Polyalphabetic cipher using keyword encryption

### 🖥️ User Interface
- Clean console-based menu system
- Intuitive navigation and error handling
- Professional formatting and user feedback

## Installation & Usage

### Prerequisites
- Python 3.6 or higher

### Running the Application
```bash
python main.py
```

### User Flow
1. **Register** → Create account with secure credentials
2. **Login** → Authenticate with username/password  
3. **Choose Cipher** → Select Atbash, Caesar, or Vigenère
4. **Encrypt/Decrypt** → Process your text with the selected cipher
5. **View Results** → See the encrypted/decrypted output

## Cipher Examples

### Atbash Cipher
```
Original: "Hello World"
Encrypted: "Svool Dliow"
```

### Caesar Cipher (Shift 3)
```
Original: "Hello World"  
Encrypted: "Khoor Zruog"
```

### Vigenère Cipher (Key: "KEY")
```
Original: "Hello World"
Encrypted: "Rijvs Uyvjn"
```

## Security Features

- ✅ Password complexity requirements
- ✅ Account lockout protection  
- ✅ Secure password hashing (SHA-256)
- ✅ Input validation and sanitization
- ✅ Graceful error handling

## File Structure

```
Application-Security-Programming/
├── main.py          # Main application file
├── users.json       # User data storage (created automatically)
└── README.md        # This file
```

## Requirements

- Python 3.6+
- Standard library modules only (json, os, re, hashlib, typing)

## License

This project is open source and available under the MIT License.

## Author

Created for Application Security Programming coursework.