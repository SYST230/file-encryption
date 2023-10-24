# GUI for the encryption application
import tkinter as tk
from tkinter import ttk, filedialog

# Create the main application window
root = tk.Tk()
root.title("Python Encryption Application")
root.geometry('500x500')

selected_file = ""

# Creates a function to open a file dialog for selecting a file
def browse_file():
    global selected_file
    selected_file = filedialog.askopenfilename()
    file_label.config(text="Selected File:" + selected_file)

# Create a function to perform encryption
def encrypt_file():
    if selected_file:
        # Implement encryption logic using the selected_file
        # encrypted_file = your_encryption_function(selected_file)
        encrypted_file = "Encrypted: " + selected_file
        result_label.config(text=encrypted_file)
    else:
        result_label.config(text="Please select a file to encrypt.")

# Create a function to perform decryption
def decrypt_file():
    if selected_file:
        # Implement decryption logic here using the selected_file

        # decrypted_file = your_decryption_function(selected_file)
        decrypted_file = "Decrypted: " + selected_file
        result_label.config(text=decrypted_file)
    else:
        result_label.config(text="Please select a file to decrypt.")

# Create a tabbed interface
tab_control = ttk.Notebook(root)

# File Selection tab
file_frame = ttk.Frame(tab_control)
tab_control.add(file_frame, text="File Selection")

browse_button = ttk.Button(file_frame, text="Select File To be encrypted or decrypted", command=browse_file)
browse_button.pack(pady=10)

file_label = ttk.Label(file_frame, text="Selected File: ")
file_label.pack()

# Encryption tab
encryption_frame = ttk.Frame(tab_control)
tab_control.add(encryption_frame, text="Encryption")

encrypt_button = ttk.Button(encryption_frame, text="Encrypt", command=encrypt_file)
encrypt_button.pack(pady=10)

# Decryption tab
decryption_frame = ttk.Frame(tab_control)
tab_control.add(decryption_frame, text="Decryption")

decrypt_button = ttk.Button(decryption_frame, text="Decrypt", command=decrypt_file)
decrypt_button.pack(pady=10)

# Result label
result_label = ttk.Label(root, text="")
result_label.pack(pady=10)

# Pack the tab control
tab_control.pack(expand=1, fill="both")

root.mainloop()