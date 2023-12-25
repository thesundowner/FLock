# What the f*ck is FLock?

FLock is a program that lets you safely encrypt / decrypt files. It uses the SHA256 
hashing and AES256 encryption algorithms. so Its the safest file 
encryption program you can find. And it's the most dangerous thing that 
can happen to your precious files if you aren't careful.


## HOW TO ENCRYPT/DECRYPT FILES?

There are certain things that are needed to be considered before
encrypting/decrypting:

1. Passwords with only whitespaces(or spaces) are allowed. 
2. If you don't use the right password during decryption, it will render 
   the file unreadable after you use the right password afterwards. This 
   will be fixed on later versions.
3. There's currently only one salt hash for all encrypted files. This will
   be fixed by using a unique salt hash on later versions. Any file locked
   prior to this change will be considered unreadable if decrypted. So be 
   cautious and we'll notify when this change occurs.

### Steps to Encrypt a File:

1. At the main menu, click on "Encrypt file."
2. Select the file you want to encrypt.
3. Input the password.
4. Write the name of the file for confirmation.
5. Voilà, Now your files are safe!

### Steps to Decrypt a file:

1. At the main menu, click on "Decrypt file."
2. Select the file you want to decrypt. (ends with ".flk")
3. Input the password.
4. Write the name of the file for  confirmation.
5. Click on "Yes" if you are sure that's the right file and correct password.

### WARNING: DO NOT decrypt a file which is not encrypted. It will CORRUPT the entire file!


## Setup and Install

There are two options. Either wait for the pre-compiled setups i make or Just install Python and continue there. If you want to convert it into an excecutable, I've made a setup script to make things easier.

Run `setup.py` assuming you've already installed the required modules using pip. If you, somehow don't know how to do it, run `python -m pip install -r requirements.txt` after you opened a terminal on the project.


