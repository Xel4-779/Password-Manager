from pathlib import Path
from cryptography.fernet import Fernet , InvalidToken
import os


SALT_FILE = Path(__name__).with_name("new_salt.bin")

random_key = Fernet.generate_key()

def random_salt():
    if SALT_FILE.exists() :
        return SALT_FILE.read_bytes()
    else:
        salt = os.urandom(16)
        SALT_FILE.write_bytes(salt)
        return salt

cipher = Fernet(random_key)

salt = cipher.decrypt(random_salt()).decode()

print("------------------------------------------------------------")
print("\n")
print(salt)
print("\n")
print("------------------------------------------------------------")

