import getpass
import json
import os
import base64

from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


DATA_FILE = Path(__file__).with_name("passwords.json")
SALT_FILE = Path(__file__).with_name("salt.bin")


password_manager = {}
cipher = None


def random_salt():
    if SALT_FILE.exists() :
        return SALT_FILE.read_bytes()
    else:
        salt = os.urandom(16)
        SALT_FILE.write_bytes(salt)
        return salt

def derive_key(master_password):
    
    kdf = PBKDF2HMAC(
    algorithm= hashes.SHA256(),
    length=32,
    salt = random_salt(),
    iterations=600_000,
    )



    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)
    

def load_passwords():
    global password_manager
    
    if DATA_FILE.exists():
        with DATA_FILE.open("r", encoding="utf-8") as file:
            password_manager = json.load(file)


def save_passwords():
    with DATA_FILE.open("w", encoding="utf-8") as file:
        json.dump(  password_manager , file , indent = 4  )



# Function 1 create account - tested
def create_account():
      

    username = input("Enter a username: ")
    password = getpass.getpass("Enter a password: ")

    password_manager[username] = cipher.encrypt(password.encode()).decode()
    print("----------------------------------------------")

    save_passwords()


#Function 2 login - tested
def login():
    username = input("Enter your username: ")

    true_password = password_manager.get(username)

    if true_password == None:
        print("Nonexisting username!")
        print("-------------------------------")
        return
    
    password = getpass.getpass("Enter your password: ") 

    decoded_password = cipher.decrypt(true_password.encode()).decode()
    
    

    if password == decoded_password:

        print("Login successful!")
        print("----------------------------------------------")
    else:   
        print("Invalid password.")
        print("----------------------------------------------")



#Function 3 change a password -tested
def decode_password_from( current_account ):
    if password_manager.get(current_account) != None:

        password =password_manager[current_account]
        decrypted_password = cipher.decrypt(password.encode()).decode()
        print(decrypted_password)

    else:
        print("Nonexisting account")
        return


#Function 4 decode a password from a given account - tested
def change_password():
    username = input("Enter your username: ")
    

    if username not in password_manager:
        print("Username does not exist.")
        print("----------------------------------------------")
        return
    else:
        password = getpass.getpass("Enter your current password: ")
        decrypted_password = cipher.decrypt(password_manager[username].encode()).decode()

    if decrypted_password == password:
        new_password = getpass.getpass("Enter your new password: ")
        password_manager[username] = cipher.encrypt(new_password.encode()).decode()


        save_passwords()


        print("Password changed successfully.")
        print("----------------------------------------------")
    else:
        print("Username or password is incorrect.")
        print("----------------------------------------------")



#Function 5 retrieve all passwords -tested
def retrieve_all_passwords():
    print("----------------------------------------------")
    print("Currently stored passwords, there are " + str(len(password_manager)) + " accounts stored: ")
    i = 1
    for account in password_manager:
        decrypted_password = cipher.decrypt(password_manager[account].encode()).decode()
        print(str(i) + ". " + account[:1].upper() + account[1:] + " : " + decrypted_password)
        i += 1

    print("----------------------------------These are all the passwords stored.")



def main():
    global cipher 

    load_passwords()

    master_password = getpass.getpass("Enter the master Password:   ")
    
    
    cipher = Fernet(derive_key(master_password))

    while True:
        
        print("----------------------------------------------")

        print("\nPassword Manager")
        print("1. Create Account")
        print("2. Login")
        print("3. Retrieve Password")
        print("4. Change Password")
        print("5. Retrieve All Passwords")

        print("Any other key to exit")
        print("----------------------------------------------")


        choice = input("Enter your choice: ")

        match choice:
            case '1':
                create_account()
            case '2':
                login()
            case '3':
                decode_password_from(input("Enter the username to retrieve the password: "))
            case '4':
                change_password()
            case '5':
                retrieve_all_passwords()
            case _:
                break




if __name__ == "__main__":
    main()

