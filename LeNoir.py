import base64
from cryptography.fernet import Fernet

print("╭╮╱╱╭╮╱╱╱╱╱╱╱╱╱╱╱╭━━━╮╱╱╱╱╱╱╱╱╭╮")
print("┃╰╮╭╯┃╱╱╱╱╱╱╱╱╱╱╱┃╭━╮┃╱╱╱╱╱╱╱╭╯╰╮")
print("╰╮┃┃╭┻━┳━━┳━━┳━━╮┃┃╱╰╋━┳╮╱╭┳━┻╮╭╋━━┳━╮")
print("╱┃╰╯┃┃━┫╭╮┃╭╮┃━━┫┃┃╱╭┫╭┫┃╱┃┃╭╮┃┃┃┃━┫╭╯")
print("╱╰╮╭┫┃━┫╭╮┃╰╯┣━━┃┃╰━╯┃┃┃╰━╯┃╰╯┃╰┫┃━┫")
print("╱/╰╯╰━━┻╯╰┻━╮┣━━╯╰━━━┻╯╰━╮╭┫╭━┻━┻━━┻╯")
print("╱╱╱╱╱╱╱╱╱╱╭━╯┃╱╱╱╱╱╱╱╱╱╭━╯┃┃┃")
print("╱╱╱╱╱╱╱╱╱╱╰━━╯╱╱╱╱╱╱╱╱╱╰━━╯╰╯")

def generate_key(password):
    # Generate a key from the password using PBKDF2
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    salt = b'salt'  # You should use a different salt for each file
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        iterations=89561,  # You can adjust this number for security
        salt=salt,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key
    

def encrypt_file(file_path, key):
    cipher_suite = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    with open(file_path + '.ve', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

def decrypt_file(encrypted_file_path, key):
    cipher_suite = Fernet(key)
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    with open(encrypted_file_path[:-3], 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

if __name__ == "__main__":
    password = input("Enter the encryption password: ")
    key = generate_key(password)

    action = input("Choose an action (encrypt or decrypt): ").strip().lower()

    if action == "encrypt":
        file_to_encrypt = input("Enter the path of the file to encrypt: ")
        encrypt_file(file_to_encrypt, key)
        print("File encrypted successfully.")
    elif action == "decrypt":
        encrypted_file = input("Enter the path of the encrypted file (.ve): ")
        decrypt_file(encrypted_file, key)
        print("File decrypted successfully.")
    else:
        print("Invalid action. Please choose 'encrypt' or 'decrypt'.")
