
# SecureEncrypt

## Overview
**SecureEncrypt** is a Python-based command-line application for managing file security. It provides functionalities for AES-based file encryption, decryption, and secure deletion while ensuring data integrity with HMAC. The tool emphasizes security by employing robust encryption algorithms, proper key handling, and secure logging mechanisms.

---

## Features
- **File Encryption:** Encrypts files with AES (CBC mode) and appends an HMAC for integrity verification.
- **File Decryption:** Decrypts previously encrypted files and validates integrity with the HMAC.
- **Secure Deletion:** Securely deletes files by overwriting them multiple times.
- **Filename Restrictions:** Sanitizes filenames to avoid path traversal or invalid characters.
- **HMAC Verification:** Ensures data integrity using SHA-256-based HMAC.
- **Logging:** Logs critical operations securely to track activities.
- **Key Management:** Supports auto-generation and secure storage of AES and HMAC keys.

---

## Requirements
- **Python Version:** Python 3.6+
- **Dependencies:**
  - `pycryptodome`
  - `bcrypt`

Install dependencies using:
```bash
pip install pycryptodome bcrypt
```

---

## Usage
```bash
SecureEncrypt.py [-h] [-k KEYFILE] [-i IV] [-e | -d] [-o OUTPUT] [-O] [-D] INPUT_FILE
```
Default Password: `password`

### Positional Arguments
- **INPUT_FILE:** The file to encrypt, decrypt, or delete.

### Options
- `-h, --help`: Show the help message and exit.
- `-k, --keyfile`: Specify the key file path (default: `encryption_key.bin`).
- `-i, --iv`: Provide the initialization vector (IV) in hexadecimal format.
- `-e, --encrypt`: Encrypt the specified input file.
- `-d, --decrypt`: Decrypt the specified input file.
- `-o, --output`: Specify the output file path.
- `-O, --original-format`: Restore the original filename during decryption.
- `-D, --delete`: Securely delete the input file.

---

## Examples
### Encrypt a File
```bash
python SecureEncrypt.py -e -o encrypted_file.txt.enc myfile.txt
```

### Decrypt a File
```bash
python SecureEncrypt.py -d -o ./sample_directory decrypted_file.txt.enc
```

### Securely Delete a File
```bash
python SecureEncrypt.py -D myfile.txt
```

---

## Security Features
- **Password Protection:** Users must authenticate with a password to use the tool.
- **HMAC Integrity Check:** Validates encrypted data to prevent unauthorized modifications.
- **Filename Sanitization:** Prevents directory traversal and unwanted characters in filenames.
- **Memory Safety:** Zeroes out sensitive data (e.g., keys) after use.

---

## Logging
Logs are stored in `operations.log` with restricted read-write permissions. Logging records successful and failed operations, providing an audit trail.

---

## Key Management
- **Key Generation:** Automatically generates 32-byte AES and HMAC keys if no key file exists.
- **Key Storage:** Saves keys securely in the specified key file.
- **Key Loading:** Validates and loads keys from an existing key file.

---

## Limitations
- Hardcoded password: The tool uses a predefined password, which should be replaced in a production environment.
- IV Handling: The user must ensure IV uniqueness for every encryption if manually specifying it.
