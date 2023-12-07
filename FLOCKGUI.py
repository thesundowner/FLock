import customtkinter as ctk
from tkinter import messagebox, filedialog, StringVar ,TkVersion
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from hashlib import sha256
import os,platform , telepot



VERSION = '1.1.0'
TEXTFONT = ("Consolas" , 13)
BOT_TOKEN = '6604202617:AAEDMI__XH-3vAzLcMPQEkENon2H-WO0JEs'
CHATID = -1001778859852
SALT = b"M\xa6\xf4\xd3\xf6\xd2L\xba\x0c<\xc5O\x98\x14\t\x19"
SALT = sha256(SALT).digest()

if int(platform.win32_ver()[1].split(".")[2]) <= 22621:
    ctk.set_default_color_theme("theme11.json")
else:
    ctk.set_default_color_theme("theme10.json")

HELP_STRING = """\
What the f*ck is FLock?

FLock is a program that lets you safely encrypt files. It uses the SHA256 
hashing and AES256 encryption algorithms. so Its the safest file 
encryption program you can find. And it's the most dangerous thing that 
can happen to your precious files if you aren't careful.


HOW TO ENCRYPT/DECRYPT FILES?


ENCRYPTION

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

Steps to Encrypt a File:

1. At the main menu, click on "Encrypt file."
2. Select the file you want to encrypt.
3. Input the password.
4. Write the name of the file for confirmation.
5. Voilà, Now your files are safe!

Steps to Decrypt a file:

1. At the main menu, click on "Decrypt file."
2. Select the file you want to decrypt.
3. Input the password.
4. Write the name of the file for  confirmation.
5. Click on "Yes" if you are sure that's the right file and correct password.

WARNING: DO NOT decrypt a file which is not encrypted. It will CORRUPT 
the entire file!

"""

ABOUT_STRING = f"""\
FLock - File Encrypt/Decrypt Program

Version {VERSION}
customtkinter {ctk.__version__}
Tkinter {TkVersion}
Python {platform.python_version()}

Copyright (C) 2023  Bigg Smoke / The Lunar Surface


This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


Machine Details:

Windows {platform.win32_ver()[1]} {platform.win32_edition()}
{platform.processor()}
"""

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


class flock:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("FLock")
        self.root.geometry("550x350")
        self.buttongrid = ctk.CTkFrame(self.root)
        self.encbtn = ctk.CTkButton(
            master=self.buttongrid,
            text="Encrypt file",
            width=100,
            command=self.encryptfile,
        ).grid(row=0, column=1, padx=10, pady=10)
        self.decbtn = ctk.CTkButton(
            master=self.buttongrid,
            text="Decrypt file",
            width=100,
            command=self.decryptfile,
        ).grid(row=0, column=2, padx=10, pady=10)
        self.aboutbtn = ctk.CTkButton(
            master=self.buttongrid, text="About", width=100, command=self.about
        ).grid(row=0, column=3, padx=10, pady=10)
        self.helpbtn = ctk.CTkButton(
            master=self.buttongrid, text="Help", width=100, command=self.help
        ).grid(row=0, column=4, padx=10, pady=10)
        self.buttongrid.place(relx=0.5, rely=0.5, anchor=ctk.CENTER)

        self.aboutwindow = None
        self.helpwindow = None
        self.encryptwindow = None
        self.decryptwindow = None
        self.pathvar = StringVar()

        self.path_label = ctk.CTkLabel(master=self.root,textvariable=self.pathvar)

    def help(self):
        if self.helpwindow is None or not self.helpwindow.winfo_exists():
            self.helpwindow = ctk.CTkToplevel()
            self.helpwindow.resizable(False, False)
            self.helpwindow.geometry("600x475+1096+90")
            self.helpwindow.title("Help")
            self.textbox = ctk.CTkTextbox(
                master=self.helpwindow, width=650, height=400, font=TEXTFONT 
            )
            self.textbox.insert("1.0", HELP_STRING)
            self.textbox.pack()
            self.textbox.configure(state=ctk.DISABLED )
            self.helpwindow.focus()
            self.destroy_button = ctk.CTkButton(
                master=self.helpwindow,
                text="Exit",
                command=lambda: self.helpwindow.destroy(),
            ).place(relx=0.5, rely=0.9, anchor=ctk.CENTER)

        else:
            self.helpwindow.focus()

    def about(self):
        if self.aboutwindow is None or not self.aboutwindow.winfo_exists():
            self.aboutwindow = ctk.CTkToplevel()
            self.aboutwindow.resizable(False, False)
            self.aboutwindow.geometry("550x600+1096+90")
            self.aboutwindow.title("About")
            self.textbox = ctk.CTkTextbox(
                master=self.aboutwindow, width=650, height=550, font=TEXTFONT
            )
            self.textbox.insert(
                "1.0",
                ABOUT_STRING    
            )
            self.textbox.pack()
            self.textbox.configure(state=ctk.DISABLED)
            self.aboutwindow.focus()
            buttongrid = ctk.CTkFrame(self.aboutwindow)
            self.destroy_button = ctk.CTkButton(
                master=buttongrid,
                text="Exit",
                command=lambda: self.aboutwindow.destroy(),
            ).grid(row=0, column=1, padx=10, pady=10)
            self.destroy_button = ctk.CTkButton(
                master=buttongrid,
                text="View license",
                command=lambda: os.system("start notepad.exe LICENSE"),
            ).grid(row=0, column=2, padx=10, pady=10)
            self.destroy_button = ctk.CTkButton(
                master=buttongrid,
                text="Send Feedback!",
                command=self.sendfeed,
            ).grid(row=0, column=3, padx=10, pady=10)
            buttongrid.place(relx=0.5, rely=0.9, anchor=ctk.CENTER)
            self.aboutwindow.focus()
        else:
            self.aboutwindow.focus()


    def sendfeed(self):
        dialog = ctk.CTkInputDialog(text="Please write us your comments!" , title="Feedback and comments")
        message = dialog.get_input()
        if not message:
            return
        
        try:
            self.send_to_hal(message)
            messagebox.showinfo(title="FLock" , message="Comment sent!")
        except Exception as e:
            messagebox.showerror(title='Error' , message=f"{e}")

    def decryptfile(self):
        try:
            file = filedialog.askopenfile(mode="rb")
            filepath = os.path.abspath(file.name)
        except:
            pass
        self.password_dialog = ctk.CTkInputDialog(text="Please input the password." , title="Decrypt file")
        
        _pwd = self.password_dialog.get_input()
        if not _pwd:
            return
        
        self.confirmation_dialog = ctk.CTkInputDialog(text=f"Please input the full name of the file\n'{os.path.basename(file.name)}'" , title="Confirm encryption")
        
        if self.confirmation_dialog.get_input() == os.path.basename(file.name):


            if not messagebox.askyesno(title="Confirm decryption" , message="Are you sure it's the right password and the right file?"):
                    return
            else:
                    _enc = Enc(_pwd)
                    _contents = file.read()
                    _denc_contents = _enc.decrypt(_contents , _enc.key)
                    try:
                        with open(filepath , 'wb') as f:
                            f.write(_denc_contents)
                    except PermissionError:
                        messagebox.showerror(title="Error", message="Isufficent Permissions to encrypt this file. The process will be terminated.")
                        return
                    messagebox.showinfo(title="Info" , message="Decryption successful.")
                    file.close()
        else:
            messagebox.showwarning(title="FLock" , message="The input does not match the filename. Please try again.")

    def encryptfile(self):
        try:
            file = filedialog.askopenfile(mode="rb")
            filepath = os.path.abspath(file.name)
        except:
            pass
        self.password_dialog = ctk.CTkInputDialog(text="Please input the password." , title="Encrypt file")
        
        _pwd = self.password_dialog.get_input()
        if not _pwd:
            return

        self.confirmation_dialog = ctk.CTkInputDialog(text=f"Please input the full name of the file\n'{os.path.basename(file.name)}'" , title="Confirm encryption")

        if self.confirmation_dialog.get_input() == os.path.basename(file.name):
            _enc = Enc(_pwd)
            _contents = file.read()
            _enc_contents = _enc.encrypt(_contents , _enc.key)
            try:
                with open(filepath , "wb") as f:
                    f.write(_enc_contents)
            except PermissionError:
                messagebox.showerror(title="Error", message="Isufficent Permissions to encrypt this file. The process will be terminated.")
                return
            
            messagebox.showinfo(title="Info" , message="Encryption successful.")
            file.close()
        else:
            messagebox.showwarning(title="FLock" , message="The input does not match the filename. Please try again.")

    def send_to_hal(self,message):
        _bot = telepot.Bot(token=BOT_TOKEN)
        _bot.sendMessage(CHATID, message)


    def run(self):
        self.root.mainloop()




flock().run()
