import getpass
import hashlib
import json
import os
import base64

from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


DATA_FILE = Path(__file__).with_name("passwords.json")
SALT_FILE = Path(__file__).with_name("salt.bin")
HASH_FILE = Path(__file__).with_name("hash.bin")

password_manager = {}
hash_manager = {}


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

    
def load_hashes():
    global hash_manager
    
    if HASH_FILE.exists():
        with HASH_FILE.open("r", encoding="utf-8") as file:
            hash_manager = json.load(file)


def save_passwords():
    with DATA_FILE.open("w", encoding="utf-8") as file:
        json.dump(  password_manager , file , indent = 4  )

def save_hashes():
    with HASH_FILE.open("w", encoding="utf-8") as file:
        json.dump(  hash_manager , file , indent = 4  )


# Function 1 create account 
def create_account():

    username = input("Enter a username: ")
    password = getpass.getpass("Enter a password: ")

    password_manager[username] = cipher.encrypt(password.encode()).decode()
    hash_manager[username] = hashlib.sha256(password.encode()).hexdigest()
    print("----------------------------------------------")

    save_passwords()
    save_hashes()


#Function 2 login - tested
def login():
    username = input("Enter your username: ")

    


    if hash_manager.get(username) is None:
        print("Nonexisting username!")
        print("-------------------------------")
        return
    
    password = getpass.getpass("Enter your password: ") 

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if password_hash == hash_manager.get(username):

        print("Login successful!")
        print("----------------------------------------------")
    else:   
        print("Invalid password.")
        print("----------------------------------------------")


#Function 3 change a password from a given account 
def change_password():

    username = input("Enter your username: ")

    if username not in password_manager:
        print("Username does not exist.")
        print("----------------------------------------------")
        return
    else:
        password = getpass.getpass("Enter your current password: ")

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if hashed_password == hash_manager.get(username):
        new_password = getpass.getpass("Enter your new password: ")
        password_manager[username] = cipher.encrypt(new_password.encode()).decode()
        hash_manager[username] = hashlib.sha256(new_password.encode()).hexdigest()

        save_passwords()
        save_hashes()

        print("Password changed successfully.")
        print("----------------------------------------------")
    else:
        print("Username or password is incorrect.")
        print("----------------------------------------------")



#Function 4 decode a password 
def decode_password_from( current_account ):
    if password_manager.get(current_account) != None:

        password =password_manager[current_account]
        decrypted_password = cipher.decrypt(password.encode()).decode()
        print(decrypted_password)

    else:
        print("Nonexisting account")
        return





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




def logger_logic():



    while True:
        print("----------------------------------------------")

        print("\nPassword Loger")
        print("1. Create Account")
        print("2. Login")
        print("3. Change Password")

        print("Any other key to exit")
        print("----------------------------------------------")
        choice = input("Enter your choice: ")

        match choice:
            case "1":
                create_account()
            case "2":
                login()
            case"3":
                change_password()
            case _:
                return



def retriever_logic():
    
    while True:
        print("----------------------------------------------")

        print("\nPassword Retriever")
        print("1. Retrieve Password")
        print("2. Retrieve All Passwords")

        print("Any other key to exit")
        print("----------------------------------------------")


        choice = input("Enter your choice: ")

        match choice:
            case '1':
                decode_password_from(input("Enter the username to retrieve the password: "))
            case '2':
                retrieve_all_passwords()
            case _:
                return




def main():
    global cipher 

    load_passwords()
    load_hashes()

    master_password = getpass.getpass("Enter the master Password:   ")
    
    cipher = Fernet(derive_key(master_password))


    print("Start---------------------")
    print("What do you need?")
    print("1. Log/Change/Create new account")
    print("2. Retrieve passwords")
    
    print("Any other key to exit")
    print("---------------------------")
    
    action =input("Insert the number of the process: ")

    acces_logger = None

    match action:
        case "1":
            acces_logger = True
        case "2":
            acces_logger = False
        case _:
            return
        
    

    

    if acces_logger == True:
        logger_logic()
        return

    retriever_logic()






if __name__ == "__main__":
    main()

