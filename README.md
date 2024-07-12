# pass-word
import os
import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode

class PasswordProtectedFileEncryption:
    def _init_(self, root):
        self.root = root
        self.root.title("Password Protected File Encryption")

        self.file_label = tk.Label(root, text="Enter file path:")
        self.file_label.pack()

        self.file_frame = tk.Frame(root)
        self.file_frame.pack()

        self.file_entry = tk.Entry(self.file_frame, width=50)
        self.file_entry.pack(side=tk.LEFT)

        self.browse_button = tk.Button(self.file_frame, text="Browse", command=self.browse_file)
        self.browse_button.pack(side=tk.LEFT)

        self.password_label = tk.Label(root, text="Enter password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(root, width=50, show="*")
        self.password_entry.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_button.pack()

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)

    def generate_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def create_header(self, salt, iv):
        return salt + iv

    def encrypt_file(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()
        fixed_password = "Sahana@2003"  # Fixed password

        if password != fixed_password:
            messagebox.showerror("Error", "Invalid password. Cannot encrypt.")
            return

        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "File not found.")
            return

        salt = os.urandom(16)
        key = self.generate_key(password, salt)

        with open(file_path, "rb") as file:
            data = file.read()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        header = self.create_header(salt, iv)
        encrypted_data = header + ciphertext

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)

        messagebox.showinfo("Success", "File encrypted successfully!")

    def decrypt_file(self):
        file_path = self.file_entry.get()
        password = self.password_entry.get()
        fixed_password = "Sahana@2003"  # Fixed password

        if password != fixed_password:
            messagebox.showerror("Error", "Invalid password. Cannot decrypt.")
            return

        if not file_path.endswith(".enc"):
            messagebox.showerror("Error", "Please select an encrypted file.")
            return

        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "Encrypted file not found.")
            return

        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        if len(encrypted_data) < 32:
            messagebox.showerror("Error", "Header is corrupted. Cannot decrypt.")
            return

        header = encrypted_data[:32]
        encrypted_data = encrypted_data[32:]

        salt = header[:16]
        iv = header[16:]

        if len(salt) != 16 or len(iv) != 16:
            messagebox.showerror("Error", "Header is corrupted. Cannot decrypt.")
            return

        key = self.generate_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = PKCS7(128).unpadder()
        try:
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError:
            messagebox.showerror("Error", "Invalid password or corrupted file.")
            return

        decrypted_file_path = file_path[:-4]  # remove .enc extension
        with open(decrypted_file_path, "wb") as file:
            file.write(plaintext)

        messagebox.showinfo("Success", "File decrypted successfully!")

if _name_ == "_main_":
    root = tk.Tk()
    app = PasswordProtectedFileEncryption(root)
    root.mainloop()
