import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# --- Constants ---
KEY_LENGTH = 32      # AES-256
SALT_SIZE = 16       # Salt size in bytes
ITERATIONS = 100000  # PBKDF2 iterations
NONCE_SIZE = 12      # Nonce size for AES-GCM
TAG_SIZE = 16        # Authentication tag size


# --- Key Derivation ---
def derive_key(password, salt):
    """Derives a cryptographic key from the password and salt."""
    return PBKDF2(password, salt, dkLen=KEY_LENGTH, count=ITERATIONS, hmac_hash_module=SHA256)


# --- Encryption ---
def encrypt_file(input_path, output_path, password):
    """Encrypts a file using AES-256-GCM."""
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_GCM)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(output_path, 'wb') as f:
        f.write(salt + cipher.nonce + tag + ciphertext)

    print(f"✅ File encrypted and saved to: {output_path}")


# --- Decryption ---
def decrypt_file(input_path, output_path, password):
    """Decrypts an AES-256-GCM encrypted file."""
    try:
        with open(input_path, 'rb') as f:
            data = f.read()

        salt = data[:SALT_SIZE]
        nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        tag = data[SALT_SIZE + NONCE_SIZE:SALT_SIZE + NONCE_SIZE + TAG_SIZE]
        ciphertext = data[SALT_SIZE + NONCE_SIZE + TAG_SIZE:]

        key = derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"✅ File decrypted and saved to: {output_path}")

    except (ValueError, KeyError):
        print("❌ Decryption failed: Incorrect password or corrupted file.")


# --- Main CLI Tool ---
def main():
    print("🔐 Secure AES-256-GCM Encryption Tool")
    choice = input("Type 'e' to Encrypt or 'd' to Decrypt: ").lower()

    if choice not in ('e', 'd'):
        print("❌ Invalid choice.")
        return

    file_path = input("Enter the path of the file: ").strip()
    if not os.path.isfile(file_path):
        print(f"❌ File not found: {file_path}")
        return

    output_path = input("Enter output file path: ").strip()

    if choice == 'e':
        password = input("Enter password: ")
        confirm_password = input("Confirm password: ")

        if password != confirm_password:
            print("❌ Passwords do not match. Aborting encryption.")
            return

        encrypt_file(file_path, output_path, password)

    else:
        password = input("Enter password: ")
        decrypt_file(file_path, output_path, password)


if __name__ == "__main__":
    main()
