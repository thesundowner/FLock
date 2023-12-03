# (C) 2023 BIGG SMOKE

import os, getpass, sys
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha256
from rich.console import Console

SALT = b"M\xa6\xf4\xd3\xf6\xd2L\xba\x0c<\xc5O\x98\x14\t\x19"
SALT = sha256(SALT).digest()


class Enc:
    def __init__(self, password):
        password = str(password)
        password = sha256(password.encode("utf-8")).hexdigest()
        self.key = self.gen_key(password, SALT)

    def gen_key(self, password, salt):
        return PBKDF2(password, salt, dkLen=32)

    def pad(self, st):
        return st + b"\0" * (AES.block_size - len(st) % AES.block_size)

    def encrypt(self, message, key):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def decrypt(self, ciphertext, key):
        try:
            iv = ciphertext[: AES.block_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            otext = cipher.decrypt(ciphertext[AES.block_size :])
            return otext.rstrip(b"\0")
        except ValueError as err:
            print(type(err).__name__)
            return


class fileobj:
    def __init__(self, file, password):
        self.file = file
        self.pwd = password
        
    def lock(self):
        with open(self.file, "rb") as f:
            c = f.read()
        c_e = Enc(self.pwd).encrypt(c, Enc(self.pwd).key)

        with open(self.file, "wb") as f:
            f.write(c_e)

    def unlock(self, password):
        with open(self.file, "rb") as f:
            c = f.read()
        c_d = Enc(password).decrypt(c, Enc(self.pwd).key)
        with open(self.file, "wb") as f:
            f.write(c_d)


def main():
    # os.system("color 0b")
    os.system("mode con: cols=46 lines=38")
    os.system("cls")
    print("_" * 46)
    print(" " * 13 + "WELCOME TO FILELOCK!\n")
    print(" " * 16 + "[1] Encrypt")
    print(" " * 16 + "[2] Decrypt\n")
    while True:
        try:
            choice = int(input(" " * 3 + "Choose an option: "))
            match choice:
                case 1:
                    enc()
                    break
                case 2:
                    denc()
                    break
                case _:
                    print("Invalid Option!")
        except ValueError:
            print("Invalid option!")


def enc():
    os.system("cls")
    print("_" * 46)
    try:
        pw = getpass.getpass(prompt=" " * 14 + "Password: ", stream=None)
        file = str(input(" " * 14 + "Input file path: "))
        f = fileobj(file, pw)
        f.lock()
        print("Finished Encrypting... Your file is now safe!")
        os.system("pause")
        exit(0)
    except FileNotFoundError:
        print("File not found. The program will now exit. ")
        os.system("pause")
    except Exception as e:
        print("Sorry, " + type(e).__name__ + " Has occured. The program will now exit.")
        exit(1)


def denc():
    os.system("cls")
    print("_" * 46)
    try:
        file = str(input(" " * 0 + "Input file path(Without surrounding quotes):\n "))
        pw = getpass.getpass(prompt=" " * 14 + "Password: ", stream=None)
        f = fileobj(file, pw)
        f.unlock(pw)
        print("Finished Decrypting... Check the file now!")
        os.system("pause")
        exit(0)
    except FileNotFoundError:
        print("File not found. The program will now exit. ")
        os.system("pause")
    except Exception as e:
        print("Sorry, " + type(e).__name__ + " Has occured. The program will now exit.")
        exit(1)


def help():
    print(
    "FILELOCK\n\n(C) 2023 THE LUNAR SURFACE\n\nDISCLAIMER: We (THE LUNAR SURFACE) will be not held responsible for bricked phones, lost important files, ransomware attacks and even the death of your cat (even though it doesn't have any correlation to the program but just for the hell of it). If you, in any way do not know how this program works, EXIT IMMEDIATELY.\n\n\n\nFILELOCK lets you encrypt and decrypt files using AES256 encryption. And it also happens to be an information corrupting program by accident. Use with caution.\n\n\nUSAGE:\n\nFILELOCK -l nuclear_launch_codes.bin password\n\nNOTE: you need to make sure that the file you want to encrypt and this script is in the same folder. Just for convience sake.\n\nARGUMENTS:\n-l   Locks the file\n-u   Unlocks the file\"\n-h   Displays this help message\n-i   Runs FILELOCK in interactive mode\n\nWARNING: Please do not decrypt a file which is not encrypted in the first place. It will corrupt the entire file!!!\nAnd keep in mind that during decryption, if you don't input the same password you used during encryption, it will output an entirely different file. So don't touch the file locked by FILELOCK if you don't know the right password. it will make it unreadable even if you supply the right password afterwards.\n\n"
)


if __name__ == "__main__":
    console = Console()
    if len(sys.argv) < 2:
        help()
        console.print('\n\n[red]Please specify an argument.[/red]')
        os.system("pause")
    elif sys.argv[1] == "-i":
        main()
    elif sys.argv[1] == "-h":
        help()
        os.system("pause")

    elif sys.argv[1] == '-l':
        f = fileobj(sys.argv[2] , sys.argv[3])
        f.lock()
        print("Done locking...")
        os.system("pause")

    elif sys.argv[1] == '-u':
        f = fileobj(sys.argv[2] , sys.argv[3])
        f.unlock()
        print("Done unlocking...")
        os.system("pause")

    else:
        help()
        print('\n\nPlease specify an argument.')
        os.system("pause")

       
