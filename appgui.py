# GUI for the encryption application
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib

# Create the main application window
root = tk.Tk()
root.title("Python Encryption Application")
root.geometry('500x500')

selected_file = ""
file_hash = ""

# Creates a function to open a file dialog for selecting a file
def browse_file():
    global selected_file
    selected_file = filedialog.askopenfilename()
    file_label_encryption.config(text="Selected File: " + selected_file)
    file_label_decryption.config(text="Selected File: " + selected_file)
    file_label_hashing.config(text="Selected File: " + selected_file)

# Create a function to perform encryption
def encrypt_file():
    global selected_file
    if selected_file:
        password = password_entry.get()  # Get the password from the entry field
        if not password:
            messagebox.showerror("Error", "Please enter a password for encryption.")
        else:
            # Implement encryption logic using the selected_file and password
            # encrypted_file = your_encryption_function(selected_file, password)
            encrypted_file = "Encrypted: " + selected_file
            messagebox.showinfo("Encryption Result", encrypted_file)
    else:
        messagebox.showerror("Error", "Please select a file to encrypt.")

# Create a function to perform decryption
def decrypt_file():
    global selected_file
    if selected_file:
        # Implement decryption logic here using the selected_file
        # decrypted_file = your_decryption_function(selected_file)
        decrypted_file = "Decrypted: " + selected_file
        messagebox.showinfo("Decryption Result", decrypted_file)
    else:
        messagebox.showerror("Error", "Please select a file to decrypt.")

# Create a function to calculate the hash of the selected file
def calculate_hash():
    global file_hash
    if selected_file:
        with open(selected_file, "rb") as file:
            file_contents = file.read()
            hash_object = hashlib.md5()  # You can choose a different hash algorithm
            hash_object.update(file_contents)
            file_hash = hash_object.hexdigest()
            file_hash_label.config(text="File Hash: " + file_hash)
    else:
        file_hash_label.config(text="File Hash: (Please select a file)")

# Create a tabbed interface
tab_control = ttk.Notebook(root)

# Encryption tab
encryption_frame = ttk.Frame(tab_control)
tab_control.add(encryption_frame, text="Encryption")

# File Selection button on Encryption tab
browse_button_encryption = ttk.Button(encryption_frame, text="Select File for Encryption", command=browse_file)
browse_button_encryption.pack(pady=10)

# Add label to display selected file on Encryption tab
file_label_encryption = ttk.Label(encryption_frame, text="Selected File: ")
file_label_encryption.pack()

# Add an entry field for password input
password_label = ttk.Label(encryption_frame, text="Enter Password:")
password_label.pack()
password_entry = ttk.Entry(encryption_frame, show="*")  # Show asterisks for password input
password_entry.pack()

# Encrypt button on Encryption tab
encrypt_button = ttk.Button(encryption_frame, text="Encrypt", command=encrypt_file)
encrypt_button.pack(pady=10)

# Decryption tab
decryption_frame = ttk.Frame(tab_control)
tab_control.add(decryption_frame, text="Decryption")

# File Selection button on Decryption tab
browse_button_decryption = ttk.Button(decryption_frame, text="Select File for Decryption", command=browse_file)
browse_button_decryption.pack(pady=10)

# Add label to display selected file on Decryption tab
file_label_decryption = ttk.Label(decryption_frame, text="Selected File: ")
file_label_decryption.pack()

# Decrypt button on Decryption tab
decrypt_button = ttk.Button(decryption_frame, text="Decrypt", command=decrypt_file)
decrypt_button.pack(pady=10)

# Hashing tab
hashing_frame = ttk.Frame(tab_control)
tab_control.add(hashing_frame, text="SSH Hashing")

# File Selection button on Hashing tab
browse_button_hashing = ttk.Button(hashing_frame, text="Select File for Hashing", command=browse_file)
browse_button_hashing.pack(pady=10)

# Add label to display selected file on Hashing tab
file_label_hashing = ttk.Label(hashing_frame, text="Selected File: ")
file_label_hashing.pack()

# Label to display the calculated hash
file_hash_label = ttk.Label(hashing_frame, text="File Hash: (Please select a file)")
file_hash_label.pack()

# Hash button on Hashing tab
hash_button = ttk.Button(hashing_frame, text="Create Hash", command=calculate_hash)
hash_button.pack(pady=10)

# Pack the tab control
tab_control.pack(expand=1, fill="both")

root.mainloop()

