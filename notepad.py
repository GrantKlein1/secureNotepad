import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import os, sys
from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

root = tk.Tk()
root.title("notepad")

text_area = tk.Text(root, wrap='word', font=("Arial", 12), undo=True, autoseparators=True, maxundo=-1)
text_area.pack(expand=True, fill='both')

current_text_size = 10

SUPPORTED_MODES = {
    "AES-256": ["GCM", "CBC", "ECB"],
    "Blowfish": ["CBC", "ECB"],
    "3DES": ["CBC", "ECB"],
}

MODE_COMPONENTS = {
    "GCM": 3,
    "CBC": 2,
    "ECB": 1,
}

BLOCK_SIZES = {
    "AES-256": AES.block_size,
    "Blowfish": Blowfish.block_size,
    "3DES": DES3.block_size,
}


def _derive_password_bytes(password):
    if not password:
        raise ValueError("Password is required for encryption.")
    return SHA256.new(password.encode("utf-8")).digest()


def _derive_key(cipher_name, password_bytes):
    if cipher_name == "AES-256":
        return password_bytes
    if cipher_name == "Blowfish":
        return password_bytes[:32]
    if cipher_name == "3DES":
        key_material = password_bytes[:24]
        while True:
            try:
                return DES3.adjust_key_parity(key_material)
            except ValueError:
                key_material = SHA256.new(key_material).digest()[:24]
    raise ValueError(f"Unsupported cipher: {cipher_name}")


def _encrypt_payload(cipher_name, mode, plaintext_bytes, password_bytes):
    key = _derive_key(cipher_name, password_bytes)
    block_size = BLOCK_SIZES[cipher_name]

    if cipher_name == "AES-256" and mode == "GCM":
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
        return [nonce, tag, ciphertext]

    if mode == "GCM":
        raise ValueError(f"{cipher_name} does not support GCM mode.")

    if mode == "CBC":
        iv = get_random_bytes(block_size)
        cipher_cls = {"AES-256": AES, "Blowfish": Blowfish, "3DES": DES3}[cipher_name]
        cipher = cipher_cls.new(key, cipher_cls.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(plaintext_bytes, block_size))
        return [iv, ciphertext]

    if mode == "ECB":
        cipher_cls = {"AES-256": AES, "Blowfish": Blowfish, "3DES": DES3}[cipher_name]
        cipher = cipher_cls.new(key, cipher_cls.MODE_ECB)
        ciphertext = cipher.encrypt(pad(plaintext_bytes, block_size))
        return [ciphertext]

    raise ValueError(f"Unsupported cipher/mode combination: {cipher_name} with {mode}")


def _decrypt_payload(cipher_name, mode, password_bytes, hex_parts):
    expected_parts = MODE_COMPONENTS.get(mode)
    if expected_parts is None:
        raise ValueError(f"Unsupported mode: {mode}")
    if len(hex_parts) != expected_parts:
        raise ValueError("Encrypted file is corrupted or mode metadata is incorrect.")

    key = _derive_key(cipher_name, password_bytes)
    block_size = BLOCK_SIZES[cipher_name]

    if cipher_name == "AES-256" and mode == "GCM":
        nonce = bytes.fromhex(hex_parts[0])
        tag = bytes.fromhex(hex_parts[1])
        ciphertext = bytes.fromhex(hex_parts[2])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    if mode == "CBC":
        iv = bytes.fromhex(hex_parts[0])
        ciphertext = bytes.fromhex(hex_parts[1])
        cipher_cls = {"AES-256": AES, "Blowfish": Blowfish, "3DES": DES3}[cipher_name]
        cipher = cipher_cls.new(key, cipher_cls.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(ciphertext), block_size)

    if mode == "ECB":
        ciphertext = bytes.fromhex(hex_parts[0])
        cipher_cls = {"AES-256": AES, "Blowfish": Blowfish, "3DES": DES3}[cipher_name]
        cipher = cipher_cls.new(key, cipher_cls.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), block_size)

    raise ValueError(f"Unsupported cipher/mode combination: {cipher_name} with {mode}")

class EncryptionOptionPopup(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Encryption Options")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.result = None
        self.cipher_var = tk.StringVar(value="AES-256")
        self.mode_var = tk.StringVar(value="GCM")

        frm = ttk.Frame(self, padding=12)
        frm.grid(sticky="nsew")

        ttk.Label(frm, text="Cipher").grid(row=0, column=0, sticky="w")
        ciphers = list(SUPPORTED_MODES.keys())
        for i, cipher in enumerate(ciphers):
            ttk.Radiobutton(
                frm,
                text=cipher,
                variable=self.cipher_var,
                value=cipher,
                command=self._on_cipher_change,
            ).grid(row=i + 1, column=0, sticky="w")

        ttk.Label(frm, text="Mode").grid(row=0, column=0, sticky="w")
        modes = list(SUPPORTED_MODES.values())[0]
        for i, mode in enumerate(modes):
            ttk.Radiobutton(
                frm,
                text=mode,
                variable=self.mode_var,
                value=mode,
            ).grid(row=i + 1, column=1, sticky="w", padx=(20, 0))

        btns = ttk.Frame(frm)
        btns.grid(row=4, column = 0, columnspan=2, pady=(12,0), sticky="e")
        ttk.Button(btns, text="Cancel", command=self.on_cancel).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(btns, text="OK", command=self.on_ok).grid(row=0, column=0, padx=(0, 5))

        self.bind("<Return>", lambda event: self.on_ok())
        self.bind("<Escape>", lambda event: self.on_cancel())
        self.update_idletasks()
        self.geometry(f"+{parent.winfo_rootx() + 40}+{parent.winfo_rooty() + 40}")

    def _on_cipher_change(self):
        modes = SUPPORTED_MODES[self.cipher_var.get()]
        self.mode_combo.configure(values=modes)
        if self.mode_var.get() not in modes:
            self.mode_combo.current(0)

    def on_cancel(self):
        self.result = None
        self.destroy()

    def on_ok(self):
        selected_cipher = self.cipher_var.get()
        selected_mode = self.mode_var.get()
        messagebox.showinfo("Selected Encryption Options", f"You selected: {selected_cipher} with {selected_mode}")
        self.result = {"cipher": selected_cipher, "mode": selected_mode}
        self.destroy()

def choose_encryption_options():
    popup = EncryptionOptionPopup(root)
    root.wait_window(popup)
    if popup.result["cipher"] == "Blowfish" and popup.result["mode"] == "GCM":
        messagebox.showerror("Invalid Selection", "Blowfish does not support GCM mode. Please choose a different combination.")
        return choose_encryption_options()
    elif popup.result["cipher"] == "3DES" and popup.result["mode"] == "GCM":
        messagebox.showerror("Invalid Selection", "3DES does not support GCM mode. Please choose a different combination.")
        return choose_encryption_options()
    return popup.result

def do_undo(event=None):
    try:
        text_area.edit_undo()
    except tk.TclError:
        pass

def do_redo(event=None):
    try:
        text_area.edit_redo()
    except tk.TclError:
        pass

def save_encrypted_file():
    options = choose_encryption_options()
    if not options:
        return 

    try:
        password = tk.simpledialog.askstring("Password", "Enter a password for encryption:", show='*')
        if not password:
            return
        password_encrypted = _derive_password_bytes(password)
    except ValueError as exc:
        messagebox.showerror("Error", str(exc))
        return
    
    file_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                             filetypes=[("Encrypted files", "*.enc")])

    if not file_path:
        return

    data = text_area.get("1.0", "end-1c").encode("utf-8")

    try:
        with open(file_path, 'w', encoding="utf-8") as f:
            f.write(f"CIPHER={options['cipher']}|MODE={options['mode']}\n")
            payload_parts = _encrypt_payload(options['cipher'], options['mode'], data, password_encrypted)
            f.write('|'.join(part.hex() for part in payload_parts))

        messagebox.showinfo("Success", "File saved and encrypted successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save encrypted file: {e}")

def asset_path(filename):
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, filename)

def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w', encoding="utf-8") as f:
            f.write(text_area.get(1.0, tk.END))
        text_area.edit_separator()

def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text/Encrypted", "*.txt *.enc"), ("Text files", "*.txt"), ("Encrypted files", "*.enc")])

    if file_path:
        with open(file_path, 'r', encoding="utf-8") as f:
            content = f.read()
        if file_path.endswith('.enc'):
            lines = content.splitlines()
            if not lines:
                messagebox.showerror("Error", "Encrypted file is empty or corrupted.")
                return
            header = lines[0]
            body = ''.join(lines[1:]).strip()
            if not body:
                messagebox.showerror("Error", "Encrypted file payload is missing.")
                return
            try:
                cipher_name = header.split('CIPHER=')[1].split('|')[0]
                mode = header.split('MODE=')[1].split('|')[0]
            except (IndexError, ValueError):
                messagebox.showerror("Error", "Encrypted file header is invalid.")
                return

            if mode not in SUPPORTED_MODES.get(cipher_name, []):
                messagebox.showerror("Error", f"Unsupported cipher/mode combination in file: {cipher_name} / {mode}")
                return

            parts = body.split('|')
            if parts and parts[-1] == '':
                parts = parts[:-1]
            try:
                password = tk.simpledialog.askstring("Password", "Enter a password for decryption:", show='*')
                if not password:
                    return
                password_encrypted = _derive_password_bytes(password)
                data = _decrypt_payload(cipher_name, mode, password_encrypted, parts)
                content = data.decode('utf-8')
            except ValueError as exc:
                messagebox.showerror("Error", f"Decryption failed: {exc}")
                return
            except Exception as exc:  # wrong password or corrupt data
                messagebox.showerror("Error", f"Unable to decrypt file: {exc}")
                return

        text_area.delete(1.0, tk.END)
        text_area.insert(tk.END, content)
        text_area.edit_reset()
        text_area.edit_modified(False)

def zoom_in():
    current_font = text_area.cget("font").split()
    font_name = current_font[0]
    font_size = int(current_font[1]) + 2
    text_area.config(font=(font_name, font_size))

def zoom_out():
    current_font = text_area.cget("font").split()
    font_name = current_font[0]
    font_size = int(current_font[1]) - 2
    if font_size >= 8:
        text_area.config(font=(font_name, font_size))

def new_file():
    if text_area.edit_modified():
        if messagebox.askyesno("Unsaved Changes", "You have unsaved changes. Do you want to save before creating a new file?"):
            if messagebox.askyesno("Encrypted/Plaintext", "Do you want to save the current file as encrypted?"):
                save_encrypted_file()
            else:
                save_file()
    text_area.delete(1.0, tk.END)
    text_area.edit_reset()
    text_area.edit_modified(False)

def set_text_size(font_size_label):
    def inner():
        size_map = {
            "title": 24,
            "subtitle": 20,
            "heading": 18,
            "subheading": 16,
            "section": 14,
            "subsection": 12,
            "body": 10
        }
        size = size_map.get(font_size_label, 10)

        if text_area.tag_ranges("sel"):
            start_index = text_area.index("sel.first")
            end_index = text_area.index("sel.last")    
            text_area.tag_add(f"size_{size}", start_index, end_index)
            text_area.tag_raise(f"size_{size}")
            text_area.tag_configure(f"size_{size}", font=(text_area.cget("font").split()[0], size))
        else:
            current_font = text_area.cget("font").split()
            font_name = current_font[0]
            text_area.config(font=(font_name, size))
        
        current_text_size = size

    return inner

def bold_text():
    if text_area.tag_ranges("sel"):
        start_index = text_area.index("sel.first")
        end_index = text_area.index("sel.last")
        text_area.tag_add("bold", start_index, end_index)
        text_area.tag_configure("bold", font=(text_area.cget("font").split()[0], current_text_size, "bold"))
    else:
        current_font = text_area.cget("font").split()
        font_name = current_font[0]
        text_area.config(font=(font_name, current_text_size, "bold"))

def italicize_text():
    if text_area.tag_ranges("sel"):
        start_index = text_area.index("sel.first")
        end_index = text_area.index("sel.last")
        text_area.tag_add("italic", start_index, end_index)
        text_area.tag_configure("italic", font=(text_area.cget("font").split()[0], current_text_size, "italic"))
    else:
        current_font = text_area.cget("font").split()
        font_name = current_font[0]
        font_size = int(current_font[1])
        text_area.config(font=(font_name, current_text_size, "italic"))

root.event_add('<<ZoomIn>>',
               '<Control-plus>',      
               '<Control-Shift-=>',    
               '<Control-=>',
               '<Control-KP_Add>')   
root.bind_all('<<ZoomIn>>', lambda event: zoom_in())
root.bind('<Control-minus>', lambda event: zoom_out())
root.event_add('<<Undo>>', '<Control-Shift-Z>', '<Control-Shift-z>', '<Control-z>')
root.bind('<<Undo>>', lambda event: text_area.edit_undo())
root.event_add('<<Redo>>', '<Control-Shift-Y>', '<Control-Shift-y>', '<Control-y>')
root.bind('<<Redo>>', lambda event: text_area.edit_redo())
root.event_add('<<Save>>', '<Control-s>', '<Control-S>')
root.bind('<<Save>>', lambda event: save_file())
root.event_add('<<SaveEncrypted>>', '<Control-E>', '<Control-e>')
root.bind('<<SaveEncrypted>>', lambda event: save_encrypted_file())
root.event_add('<<Open>>', '<Control-o>', '<Control-O>')
root.bind('<<Open>>', lambda event: open_file())
root.event_add('<<NewFile>>', '<Control-n>', '<Control-N>')
root.bind('<<NewFile>>', lambda event: new_file())
root.bind('<Control-b>', lambda event: bold_text())
root.bind('<Control-i>', lambda event: italicize_text())


icon_file = asset_path("images/notepadIcon.png")
app_image = None

if os.path.exists(icon_file):
    try:
        app_image = tk.PhotoImage(file=icon_file)
        root.iconphoto(True, app_image)
    except Exception as e:
        print(f"Error loading icon: {e}")
else:
    print("Icon file not found.")

menu_bar = tk.Menu(root)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="New", accelerator="Ctrl+N", command=new_file)
file_menu.add_command(label="Open", accelerator="Ctrl+O", command=open_file)
file_menu.add_command(label="Save", accelerator="Ctrl+S", command=save_file)
file_menu.add_command(label="Save Encrypted", accelerator="Ctrl+E", command=save_encrypted_file)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)
menu_bar.add_cascade(label="File", menu=file_menu)

edit_menu = tk.Menu(menu_bar, tearoff=0)
edit_menu.add_command(label="Undo", accelerator="Ctrl+Z", command=do_undo)
edit_menu.add_command(label="Redo", accelerator="Ctrl+Y", command=do_redo)
menu_bar.add_cascade(label="Edit", menu=edit_menu)

view_menu = tk.Menu(menu_bar, tearoff=0)
view_menu.add_command(label="Zoom In", accelerator="Ctrl+", command=zoom_in)
view_menu.add_command(label="Zoom Out", accelerator="Ctrl-", command=zoom_out)
menu_bar.add_cascade(label="View", menu=view_menu)

text_size_menu = tk.Menu(menu_bar, tearoff=0)
text_size_menu.add_command(label="Title", command=set_text_size("title"))
text_size_menu.add_command(label="Subtitle", command=set_text_size("subtitle"))
text_size_menu.add_command(label="Heading", command=set_text_size("heading"))
text_size_menu.add_command(label="Subheading", command=set_text_size("subheading"))
text_size_menu.add_command(label="Section", command=set_text_size("section"))
text_size_menu.add_command(label="Subsection", command=set_text_size("subsection"))
text_size_menu.add_command(label="Body", command=set_text_size("body"))
menu_bar.add_cascade(label="H1", menu=text_size_menu)

bold_menu = tk.Menu(menu_bar, tearoff=0)
bold_menu.add_command(label="Bold", command=bold_text)
menu_bar.add_cascade(label="B", menu=bold_menu)

italics_menu = tk.Menu(menu_bar, tearoff=0)
italics_menu.add_command(label="Italics", command=italicize_text)
menu_bar.add_cascade(label="I", menu=italics_menu)

root.config(menu=menu_bar)
root.mainloop()