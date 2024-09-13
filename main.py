import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
from Crypto.Cipher import DES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad
import os


def derive_key(password, salt):
    return scrypt(password.encode(), salt, key_len=8, N=2 ** 14, r=8, p=1)


def encrypt_des(key, plaintext, mode):
    if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
    elif mode == 'OFB':
        cipher = DES.new(key, DES.MODE_OFB)
    else:
        raise ValueError("Invalid mode. Use 'ECB' or 'OFB'.")

    return cipher.encrypt(pad(plaintext, DES.block_size))


def image_to_bytes(image):
    return np.array(image).tobytes()


def bytes_to_image(data, original_shape):
    flat_size = original_shape[0] * original_shape[1] * 3
    if len(data) > flat_size:
        data = data[:flat_size]
    elif len(data) < flat_size:
        data = data.ljust(flat_size, b'\0')

    return Image.fromarray(np.frombuffer(data, dtype=np.uint8).reshape(original_shape))


class PhotoEncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Photo Encryption App")

        self.label = tk.Label(master, text="Select an image file and enter a password")
        self.label.pack()

        self.select_button = tk.Button(master, text="Select Image", command=self.select_image)
        self.select_button.pack()

        self.password_label = tk.Label(master, text="Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(master, show="*")
        self.password_entry.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_image)
        self.encrypt_button.pack()

        self.image_path = None
        self.ecb_image = None
        self.ofb_image = None

    def select_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg *.png")])
        if self.image_path:
            self.label.config(text=f"Selected image: {self.image_path}")

    def encrypt_image(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return

        try:
            with Image.open(self.image_path) as img:
                original_shape = img.size + (3,)  # (width, height, channels)
                plaintext = image_to_bytes(img)

            salt = b'salt1234'  # In a real-world scenario, use a random salt and store it securely
            key = derive_key(password, salt)

            ecb_ciphertext = encrypt_des(key, plaintext, 'ECB')
            self.ecb_image = bytes_to_image(ecb_ciphertext, original_shape)

            ofb_ciphertext = encrypt_des(key, plaintext, 'OFB')
            self.ofb_image = bytes_to_image(ofb_ciphertext, original_shape)

            self.show_encrypted_images()

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def show_encrypted_images(self):
        encrypted_window = tk.Toplevel(self.master)
        encrypted_window.title("Encrypted Images")

        # ECB Image
        ecb_frame = tk.Frame(encrypted_window)
        ecb_frame.pack(side=tk.LEFT, padx=10, pady=10)

        ecb_label = tk.Label(ecb_frame, text="ECB Encrypted")
        ecb_label.pack()

        ecb_image = self.ecb_image.copy()
        ecb_image.thumbnail((300, 300))  # Resize for display
        ecb_photo = ImageTk.PhotoImage(ecb_image)
        ecb_image_label = tk.Label(ecb_frame, image=ecb_photo)
        ecb_image_label.image = ecb_photo
        ecb_image_label.pack()

        ecb_save_button = tk.Button(ecb_frame, text="Save ECB Image",
                                    command=lambda: self.save_image(self.ecb_image, "ecb"))
        ecb_save_button.pack()

        # OFB Image
        ofb_frame = tk.Frame(encrypted_window)
        ofb_frame.pack(side=tk.RIGHT, padx=10, pady=10)

        ofb_label = tk.Label(ofb_frame, text="OFB Encrypted")
        ofb_label.pack()

        ofb_image = self.ofb_image.copy()
        ofb_image.thumbnail((300, 300))  # Resize for display
        ofb_photo = ImageTk.PhotoImage(ofb_image)
        ofb_image_label = tk.Label(ofb_frame, image=ofb_photo)
        ofb_image_label.image = ofb_photo
        ofb_image_label.pack()

        ofb_save_button = tk.Button(ofb_frame, text="Save OFB Image",
                                    command=lambda: self.save_image(self.ofb_image, "ofb"))
        ofb_save_button.pack()

    def save_image(self, image, mode):
        original_dir = os.path.dirname(self.image_path)
        original_name = os.path.splitext(os.path.basename(self.image_path))[0]
        save_path = filedialog.asksaveasfilename(
            initialdir=original_dir,
            initialfile=f"{original_name}_{mode}_encrypted.png",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if save_path:
            image.save(save_path)
            messagebox.showinfo("Success", f"Encrypted image saved as:\n{save_path}")


def main():
    root = tk.Tk()
    app = PhotoEncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()