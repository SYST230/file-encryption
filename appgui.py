# GUI for the encryption application
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from os.path import expanduser
import filehandling


class EncryptionApp(tk.Tk):
    def __init__(self):
        super().__init__()
        # Create the main application window
        self.title("Python Encryption Application")
        self.geometry('500x300')
        self.selected_file = ""
        self.file_hash = ""
        self.build()
        self.mainloop()

    def build(self):
        # Create a tabbed interface
        tab_control = ttk.Notebook(self)
        # Encryption tab
        encryption_frame = _EncryptionFrame(tab_control)
        tab_control.add(encryption_frame, text="Encryption")
        # Decryption tab
        decryption_frame = _DecryptionFrame(tab_control)
        tab_control.add(decryption_frame, text="Decryption")
        # Hashing tab
        hashing_frame = _HashingFrame(tab_control)
        tab_control.add(hashing_frame, text="Hashing")
        # Pack the tab control
        tab_control.pack(expand=1, fill="both")


class _EncryptionFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.algorithm = tk.StringVar()
        self.algorithm.set('AES-256')
        self.build()

    def build(self):
        # Put the file selection business on one line
        file_select_frame = tk.Frame(self)
        file_select_frame.pack(fill='x')
        tk.Label(file_select_frame, text='Selected file:').pack(side='left', padx=10)
        # Label to display selected file
        self.file_selection = tk.Entry(file_select_frame, width=40)
        self.file_selection.pack(side='left', fill='x')
        # File Selection button
        tk.Button(file_select_frame, text='...', command=self.browse_file).pack(side='left')

        # Put the algorithm selection business on one line
        algorithm_select_frame = tk.Frame(self)
        algorithm_select_frame.pack(fill='x')
        tk.Label(algorithm_select_frame, text='Encryption algorithm:').pack(side='left', padx=10)
        algorithms = ['AES-256', 'Fernet', 'RSA']
        drop_down = tk.OptionMenu(algorithm_select_frame, self.algorithm, *algorithms, command=self.algorithm_changed)
        drop_down.pack(side='left')

        # Put the folder selection business on one line
        folder_select_frame = tk.Frame(self)
        folder_select_frame.pack(fill='x')
        tk.Label(folder_select_frame, text='Save location:').pack(side='left', padx=10)
        # Label to display selected folder
        self.folder_selection = tk.Entry(folder_select_frame, width=40)
        self.folder_selection.pack(side='left', fill='x')
        # Folder Selection button
        tk.Button(folder_select_frame, text='...', command=self.browse_folder).pack(side='left')

        # Add a generic password setting frame
        self.password_frame = tk.Frame(self)
        tk.Label(self.password_frame, text='Enter Password:').pack()
        self.password_entry = tk.Entry(self.password_frame, show="*")  # Show asterisks for password input
        self.password_entry.pack()

        # Add a key setting frame
        self.key_frame = tk.Frame(self)
        # Make key file selection one line
        key_select_frame = tk.Frame(self.key_frame)
        key_select_frame.pack(fill='x')
        tk.Label(key_select_frame, text='Public key:').pack(side='left', padx=10)
        # Label to display selected key
        self.key_selection = tk.Entry(key_select_frame, width=40)
        self.key_selection.pack(side='left', fill='x')
        # Key selection button
        tk.Button(key_select_frame, text='...', command=self.browse_key).pack(side='left')
        # Key generation button
        tk.Button(self.key_frame, text='Generate key pair', command=self.generate_keys).pack()

        self.current_settings = self.password_frame
        self.algorithm_changed(self.algorithm.get())
        # Encrypt button
        tk.Button(self, text='Encrypt', command=self.encrypt_file).pack(side='bottom', pady=10)

    def algorithm_changed(self, new_algorithm):
        self.current_settings.pack_forget()
        if new_algorithm in ('AES-256', 'Fernet'):
            self.current_settings = self.password_frame
            self.password_frame.pack(fill='x')
            self.password_entry.delete(0, tk.END)
        elif new_algorithm in ('RSA'):
            self.current_settings = self.key_frame
            self.key_frame.pack(fill='x')
            self.key_selection.delete(0, tk.END)

    def generate_keys(self):
        messagebox.showinfo('RSA Key Generation', 'Select a location to save the new RSA key pair to.')
        save_location = _get_foldername()
        if save_location == '':
            return
        # TODO eventually it'd be nice to ask the user for a custom name for the key
        name = 'rsa_key'
        public, _ = filehandling.generate_rsa_keys(name, save_location)
        self.key_selection.delete(0, tk.END)
        self.key_selection.insert(0, public)

    def encrypt_file(self):
        if self.file_selection.get().strip() == '':
            messagebox.showinfo(message='Please select a file to encrypt!')
            return
        try:
            if self.algorithm.get() == 'Fernet':
                filehandling.file_encrypt_fernet(
                    self.file_selection.get().strip(),
                    self.password_entry.get().strip(),
                    self.folder_selection.get().strip()
                )
                messagebox.showinfo(message='Done!')
            elif self.algorithm.get() == 'AES-256':
                filehandling.file_encrypt_aes(
                    self.file_selection.get().strip(),
                    self.password_entry.get().strip(),
                    self.folder_selection.get().strip()
                )
                messagebox.showinfo(message='Done!')
            elif self.algorithm.get() == 'RSA':
                filehandling.file_encrypt_rsa(
                    self.file_selection.get().strip(),
                    self.key_selection.get().strip(),
                    self.folder_selection.get().strip()
                )
                messagebox.showinfo(message='Done!')
        except (ValueError, FileNotFoundError) as e:
            messagebox.showerror(message=f'An error occurred: {e}')

    def browse_file(self):
        selected_file = _get_filename()
        if selected_file.strip() == '':
            return
        self.file_selection.delete(0, tk.END)
        self.file_selection.insert(0, f'{selected_file}')

    def browse_folder(self):
        selected_folder = _get_foldername()
        if selected_folder.strip() == '':
            return
        self.folder_selection.delete(0, tk.END)
        self.folder_selection.insert(0, f'{selected_folder}')

    def browse_key(self):
        selected_file = _get_filename()
        if selected_file.strip() == '':
            return
        self.key_selection.delete(0, tk.END)
        self.key_selection.insert(0, f'{selected_file}')


class _DecryptionFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.selected_file = ''
        self.algorithm = tk.StringVar()
        self.algorithm.set('AES-256')
        self.build()

    def build(self):
        # Put the file selection business on one line
        file_select_frame = tk.Frame(self)
        file_select_frame.pack(fill='x')
        tk.Label(file_select_frame, text='Selected file:').pack(side='left', padx=10)
        # Label to display selected file
        self.file_selection = tk.Entry(file_select_frame, width=40)
        self.file_selection.pack(side='left', fill='x')
        # File Selection button
        tk.Button(file_select_frame, text='...', command=self.browse_file).pack(side='left')

        # Put the algorithm selection business on one line
        algorithm_select_frame = tk.Frame(self)
        algorithm_select_frame.pack(fill='x')
        tk.Label(algorithm_select_frame, text='Decryption algorithm:').pack(side='left', padx=10)
        algorithms = ['AES-256', 'Fernet', 'RSA']
        drop_down = tk.OptionMenu(algorithm_select_frame, self.algorithm, *algorithms, command=self.algorithm_changed)
        drop_down.pack(side='left')

        # Put the folder selection business on one line
        folder_select_frame = tk.Frame(self)
        folder_select_frame.pack(fill='x')
        tk.Label(folder_select_frame, text='Save location:').pack(side='left', padx=10)
        # Label to display selected folder
        self.folder_selection = tk.Entry(folder_select_frame, width=40)
        self.folder_selection.pack(side='left', fill='x')
        # Folder Selection button
        tk.Button(folder_select_frame, text='...', command=self.browse_folder).pack(side='left')

        # Add a generic password setting frame
        self.password_frame = tk.Frame(self)
        tk.Label(self.password_frame, text='Enter Password:').pack()
        self.password_entry = tk.Entry(self.password_frame, show="*")  # Show asterisks for password input
        self.password_entry.pack()

        # Add a key setting frame
        self.key_frame = tk.Frame(self)
        # Make key file selection one line
        key_select_frame = tk.Frame(self.key_frame)
        key_select_frame.pack(fill='x')
        tk.Label(key_select_frame, text='Private key:').pack(side='left', padx=10)
        # Label to display selected key
        self.key_selection = tk.Entry(key_select_frame, width=40)
        self.key_selection.pack(side='left', fill='x')
        # Key selection button
        tk.Button(key_select_frame, text='...', command=self.browse_key).pack(side='left')

        self.current_settings = self.password_frame
        self.algorithm_changed(self.algorithm.get())
        # Decrypt button
        tk.Button(self, text='Decrypt', command=self.decrypt_file).pack(side='bottom', pady=10)

    def algorithm_changed(self, new_algorithm):
        self.current_settings.pack_forget()
        if new_algorithm in ('AES-256', 'Fernet'):
            self.current_settings = self.password_frame
            self.password_frame.pack(fill='x')
            self.password_entry.delete(0, tk.END)
        elif new_algorithm in ('RSA'):
            self.current_settings = self.key_frame
            self.key_frame.pack(fill='x')
            self.key_selection.delete(0, tk.END)

    def decrypt_file(self):
        if self.file_selection.get().strip() == '':
            messagebox.showinfo(message='Please select a file to decrypt!')
            return
        try:
            if self.algorithm.get() == 'Fernet':
                filehandling.file_decrypt_fernet(
                    self.file_selection.get().strip(),
                    self.password_entry.get().strip(),
                    self.folder_selection.get().strip()
                )
                messagebox.showinfo(message='Done!')
            elif self.algorithm.get() == 'AES-256':
                filehandling.file_decrypt_aes(
                    self.file_selection.get().strip(),
                    self.password_entry.get().strip(),
                    self.folder_selection.get().strip()
                )
                messagebox.showinfo(message='Done!')
            elif self.algorithm.get() == 'RSA':
                filehandling.file_decrypt_rsa(
                    self.file_selection.get().strip(),
                    self.key_selection.get().strip(),
                    self.folder_selection.get().strip()
                )
                messagebox.showinfo(message='Done!')
        except (ValueError, FileNotFoundError) as e:
            messagebox.showerror(message=f'An error occurred: {e}')

    def browse_file(self):
        selected_file = _get_filename()
        if selected_file.strip() == '':
            return
        self.file_selection.delete(0, tk.END)
        self.file_selection.insert(0, f'{selected_file}')

    def browse_folder(self):
        selected_folder = _get_foldername()
        if selected_folder.strip() == '':
            return
        self.folder_selection.delete(0, tk.END)
        self.folder_selection.insert(0, f'{selected_folder}')

    def browse_key(self):
        selected_file = _get_filename()
        if selected_file.strip() == '':
            return
        self.key_selection.delete(0, tk.END)
        self.key_selection.insert(0, f'{selected_file}')


class _HashingFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.algorithm = tk.StringVar()
        self.algorithm.set('SHA-256')
        self.build()

    def build(self):
        # Put the file selection business on one line
        file_select_frame = tk.Frame(self)
        file_select_frame.pack(fill='x')
        tk.Label(file_select_frame, text='Selected file:').pack(side='left', padx=10)
        # Label to display selected file
        self.file_selection = tk.Entry(file_select_frame, width=40)
        self.file_selection.pack(side='left', fill='x')
        # File Selection button
        tk.Button(file_select_frame, text='...', command=self.browse_file).pack(side='left')

        # Put the algorithm selection business on one line
        algorithm_select_frame = tk.Frame(self)
        algorithm_select_frame.pack(fill='x')
        tk.Label(algorithm_select_frame, text='Hashing algorithm:').pack(side='left', padx=10)
        algorithms = ['SHA-256', 'MD5']
        drop_down = tk.OptionMenu(algorithm_select_frame, self.algorithm, *algorithms)
        drop_down.pack(side='left')

        # Hash button
        tk.Button(self, text='Hash!', command=self.hash_file).pack(pady=10)
        # Text to display the calculated hash
        self.file_hash_text = tk.Text(self, width=40, height=2)
        self.file_hash_text.pack()

    def browse_file(self):
        selected_file = _get_filename()
        if selected_file.strip() == '':
            return
        self.file_selection.delete(0, tk.END)
        self.file_selection.insert(0, f'{selected_file}')

    def hash_file(self):
        if self.file_selection.get().strip() == '':
            messagebox.showinfo(message='Please select a file to hash!')
            return
        try:
            if self.algorithm.get() == 'SHA-256':
                hash = filehandling.file_hash_sha256(self.file_selection.get())
            elif self.algorithm.get() == 'MD5':
                hash = filehandling.file_hash_md5(self.file_selection.get())
        except FileNotFoundError as e:
            messagebox.showerror(message=f'An error occurred: {e}')
            return
        self.file_hash_text.delete(1.0, tk.END)
        self.file_hash_text.insert(1.0, hash)


def _get_filename():
    file = filedialog.askopenfilename(initialdir=expanduser('~'))
    if file == ():
        return ''
    else:
        return file


def _get_foldername():
    folder = filedialog.askdirectory(initialdir=expanduser('~'))
    if folder == ():
        return ''
    else:
        return folder
