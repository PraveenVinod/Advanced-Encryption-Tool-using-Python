# Advanced-Encryption-Tool-using-Python

**Developed by: _Praveen Vinod_**

⚠️ _This project is intended for educational and research purposes only. Use responsibly within authorized environments._

---

## 📌 Overview

The **AES-256-GCM File Encryption Tool** is a secure and user-friendly Python utility to encrypt and decrypt files using the robust **AES-256-GCM** encryption standard.

It ensures:
- 🔒 **Confidentiality:** Protects the file content from unauthorized access.
- 🛡️ **Integrity:** Ensures that decrypted files have not been tampered with.
- 🔑 **Authentication:** Validates correct decryption using an authentication tag.

---

## 🔍 Key Features

- ✅ Encrypt any file using **AES-256 in GCM mode**
- ✅ Decrypt encrypted files securely with password verification
- ✅ Password-based encryption using **PBKDF2 with SHA-256**
- ✅ Authenticated encryption with an integrity tag
- ✅ Command-line interface (CLI) for interactive usage

---

## 🛠️ Installation & Setup

### ✅ Prerequisites
- Python 3.x installed

### 📦 Required Python Libraries
- [`pycryptodome`](https://pypi.org/project/pycryptodome/)
- `getpass` (standard library)

### 📥 Installation
Install dependencies via pip: `pip install pycryptodome`

---

### 📁 Folder Structure
AES-Encryption-Tool/
- tool.py -> # Main Python script
- example_files/  -> #Folder to test encryption/decryption
- encrypted_output/  -> #Destination folder for encrypted files
- decrypted_output/  -> #Destination folder for encrypted files

---

### ⚙️ Usage

- Step 1: Prepare Your Files - Place files to encrypt inside example_files/ or any folder you prefer.
- Step 2: Run the Program - `python tool.py`
- Step 3: Follow CLI Prompts - Choose: e to Encrypt a file, d to Decrypt a file : Provide the file path, output path, and password.

---

### 🔐 Cryptographic Techniques Used

- **AES-256-GCM:** Advanced Encryption Standard with 256-bit key in Galois/Counter Mode
- **PBKDF2:** Secure password-derived key using SHA-256, 16-byte salt, 100,000 iterations
- **Authentication Tag:** Ensures data integrity upon decryption

| Component          | Size     |
| ------------------ | -------- |
| Salt               | 16 bytes |
| Nonce              | 12 bytes |
| Authentication Tag | 16 bytes |
| Ciphertext         | Variable |

---

### 🧠 Use Cases

- 🗄️ Secure sensitive personal and business files
- 📤 Securely transfer files over the internet
- 🔐 Encrypt backups to prevent data breaches
- 🔎 Verify integrity and confidentiality of stored data

---

### ✨ Future Enhancements

- Add support for large files with chunk-based encryption
- Integrate file integrity verification with SHA checksums
- Implement GUI with Tkinter or PyQt
- Add multi-user key management system
- Enable CLI argument parsing for automation

---

### 📑 Internship Details

- **🏢 Company:** CODTECH IT SOLUTIONS  
- **🆔 Intern ID:** CT06DG644  
- **📂 Domain:** Cyber Security & Ethical Hacking  
- **⏳ Duration:** 6 Weeks  
- **👨‍🏫 Mentor:** Neela Santosh  
