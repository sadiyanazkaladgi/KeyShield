# 🔐 KeyShield

### A Cryptographic Framework for Secure Message Encryption and Data Integrity Verification

KeyShield is a Python cybersecurity mini-project that demonstrates secure message encryption, decryption, and file integrity verification through an interactive web application.

## Features

- AES-256-GCM authenticated message encryption
- Password-based key generation using PBKDF2-HMAC-SHA256
- SHA-256 file hash generation
- File integrity verification
- Local activity history
- Interactive dark-themed interface

## Technologies Used

- Python
- Streamlit
- PyCryptodome
- AES-GCM
- PBKDF2-HMAC-SHA256
- SHA-256

## How to Run

1. Download or clone this repository.
2. Install Python on your computer.
3. Open a terminal in the project folder.
4. Install the required packages:

   `pip install -r requirements.txt`

5. Start the application:

   `streamlit run app.py`

## How to Use

1. Enter a message and password on the Encrypt page.
2. Encrypt the message and save the ciphertext.
3. Open the Decrypt page and enter the ciphertext and original password.
4. Use Integrity Lab to generate a file's SHA-256 hash.
5. Compare the hash with a trusted hash to check whether the file has changed.

## Security Notes

- Keep your password private.
- AES-GCM detects tampering with encrypted data.
- File integrity checks are meaningful when compared against a trusted hash.
- This project is for educational purposes and has not been independently security-audited.

## Project Objective

KeyShield demonstrates practical applications of cryptography and network security using Python.
information will be added soon.
