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

# Allowed cipher/mode pairs that wil work and the UI will accept.
# AES supports all three while Blowfish and 3DES only support CBC/ECB.
SUPPORTED_MODES = {
    "AES-256": ["GCM", "CBC", "ECB"],
    "Blowfish": ["CBC", "ECB"],
    "3DES": ["CBC", "ECB"],
}

# Number of hex components expected in the serialized payload line for each mode.
# GCM: nonce|tag|ciphertext, CBC: iv|ciphertext|digest, ECB: ciphertext|digest
MODE_COMPONENTS = {
    "GCM": 3,
    "CBC": 3,
    "ECB": 2,
}

BLOCK_SIZES = {
    "AES-256": AES.block_size,
    "Blowfish": Blowfish.block_size,
    "3DES": DES3.block_size,
}


# Wipes the contents of bytes so password is not saved.
def _wipe_bytes(buffer):
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0
    elif isinstance(buffer, memoryview):
        buffer[:] = b"\x00" * len(buffer)
        buffer.release()


# Derives a 32-byte key material from a password using SHA-256
def _derive_password_bytes(password):
    if not password:
        raise ValueError("Password is required for encryption.")
    digest = SHA256.new(password.encode("utf-8")).digest()
    return bytearray(digest)


# Produces a cipher specific key from password bytes
def _derive_key(cipher_name, password_bytes):
    """Derive a key sized appropriately for the selected cipher.
    - AES-256 uses the full 32-byte digest
    - Blowfish uses up to 32 bytes
    - 3DES requires 24-byte parity-adjusted key"""
    if cipher_name == "AES-256":
        return bytearray(password_bytes)
    if cipher_name == "Blowfish":
        return bytearray(password_bytes[:32])
    if cipher_name == "3DES":
        key_material = bytearray(password_bytes[:24])
        while True:
            try:
                adjusted = DES3.adjust_key_parity(bytes(key_material))
                return bytearray(adjusted)
            except ValueError:
                key_material = bytearray(SHA256.new(bytes(key_material)).digest()[:24])
    raise ValueError(f"Unsupported cipher: {cipher_name}")


# Encrypts plaintext according to the chosen cipher mode combo
def _encrypt_payload(cipher_name, mode, plaintext_bytes, password_bytes):
    key = _derive_key(cipher_name, password_bytes)
    block_size = BLOCK_SIZES[cipher_name]
    result = None
    try:
        if cipher_name == "AES-256" and mode == "GCM":
            nonce = get_random_bytes(12)
            cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
            result = [nonce, tag, ciphertext]
        elif mode == "GCM":
            raise ValueError(f"{cipher_name} does not support GCM mode.")
        elif mode == "CBC":
            iv = get_random_bytes(block_size)
            cipher_cls = {"AES-256": AES, "Blowfish": Blowfish, "3DES": DES3}[cipher_name]
            cipher = cipher_cls.new(bytes(key), cipher_cls.MODE_CBC, iv=iv)
            # PKCS#7-like padding then encrypt; compute digest for integrity check
            ciphertext = cipher.encrypt(pad(plaintext_bytes, block_size))
            digest = SHA256.new(plaintext_bytes).digest()
            result = [iv, ciphertext, digest]
        elif mode == "ECB":
            cipher_cls = {"AES-256": AES, "Blowfish": Blowfish, "3DES": DES3}[cipher_name]
            cipher = cipher_cls.new(bytes(key), cipher_cls.MODE_ECB)
            # ECB has no IV; pad and add digest for integrity
            ciphertext = cipher.encrypt(pad(plaintext_bytes, block_size))
            digest = SHA256.new(plaintext_bytes).digest()
            result = [ciphertext, digest]
        else:
            raise ValueError(f"Unsupported cipher/mode combination: {cipher_name} with {mode}")
        return result
    finally:
        _wipe_bytes(key)


# Decrypts for passed in cipher mode combo
def _decrypt_payload(cipher_name, mode, password_bytes, hex_parts):
    expected_parts = MODE_COMPONENTS.get(mode)
    if expected_parts is None:
        raise ValueError(f"Unsupported mode: {mode}")
    if len(hex_parts) != expected_parts:
        raise ValueError("Encrypted file is corrupted or mode metadata is incorrect.")

    key = _derive_key(cipher_name, password_bytes)
    block_size = BLOCK_SIZES[cipher_name]
    try:
        if cipher_name == "AES-256" and mode == "GCM":
            nonce = bytes.fromhex(hex_parts[0])
            tag = bytes.fromhex(hex_parts[1])
            ciphertext = bytes.fromhex(hex_parts[2])
            cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag)

        if mode == "CBC":
            iv = bytes.fromhex(hex_parts[0])
            ciphertext = bytes.fromhex(hex_parts[1])
            digest = bytes.fromhex(hex_parts[2])
            cipher_cls = {"AES-256": AES, "Blowfish": Blowfish, "3DES": DES3}[cipher_name]
            cipher = cipher_cls.new(bytes(key), cipher_cls.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(ciphertext), block_size)
            if SHA256.new(plaintext).digest() != digest:
                raise ValueError("Integrity check failed (wrong password or corrupted file).")
            return plaintext

        if mode == "ECB":
            ciphertext = bytes.fromhex(hex_parts[0])
            digest = bytes.fromhex(hex_parts[1])
            cipher_cls = {"AES-256": AES, "Blowfish": Blowfish, "3DES": DES3}[cipher_name]
            cipher = cipher_cls.new(bytes(key), cipher_cls.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), block_size)
            if SHA256.new(plaintext).digest() != digest:
                raise ValueError("Integrity check failed (wrong password or corrupted file).")
            return plaintext

        raise ValueError(f"Unsupported cipher/mode combination: {cipher_name} with {mode}")
    finally:
        _wipe_bytes(key)

# Popup dialog for choosing cipher and mode
class EncryptionOptionPopup(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Encryption Options")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.result = None
        self.cipher_var = tk.StringVar(value="AES-256")
        self.mode_var = tk.StringVar(value="CBC")

        frm = ttk.Frame(self, padding=12)
        frm.grid(sticky="nsew")

        # Use labeled frames to keep groups aligned and avoid visual offset
        cipher_group = ttk.Labelframe(frm, text="Cipher")
        cipher_group.grid(row=0, column=0, padx=(0, 12), sticky="nw")
        ciphers = list(SUPPORTED_MODES.keys())
        for i, cipher in enumerate(ciphers):
            ttk.Radiobutton(
                cipher_group,
                text=cipher,
                variable=self.cipher_var,
                value=cipher,
            ).grid(row=i, column=0, sticky="w")

        mode_group = ttk.Labelframe(frm, text="Mode")
        mode_group.grid(row=0, column=1, sticky="nw")
        mode_frame = ttk.Frame(mode_group)
        mode_frame.grid(row=0, column=0, sticky="w")
        modes = ["GCM", "CBC", "ECB"]
        for i, mode in enumerate(modes):
            ttk.Radiobutton(
                mode_frame,
                text=mode,
                variable=self.mode_var,
                value=mode,
            ).grid(row=i+1, column=1, sticky="w", padx=(0, 8))
        if self.mode_var.get() not in modes:
            self.mode_var.set("CBC")
        
        btns = ttk.Frame(frm)
        btns.grid(row=1, column = 0, columnspan=2, pady=(12,0), sticky="e")
        ttk.Button(btns, text="Cancel", command=self.on_cancel).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(btns, text="OK", command=self.on_ok).grid(row=0, column=0, padx=(0, 5))

        self.bind("<Return>", lambda event: self.on_ok())
        self.bind("<Escape>", lambda event: self.on_cancel())
        self.update_idletasks()
        self.geometry(f"+{parent.winfo_rootx() + 40}+{parent.winfo_rooty() + 40}")

    def on_cancel(self):
        self.result = None
        self.destroy()

    def on_ok(self):
        selected_cipher = self.cipher_var.get()
        selected_mode = self.mode_var.get()
        if selected_mode not in SUPPORTED_MODES[selected_cipher]:
            messagebox.showerror("Invalid Selection", f"{selected_cipher} does not support {selected_mode} mode.")
            return
        messagebox.showinfo("Selected Encryption Options", f"You selected: {selected_cipher} with {selected_mode}")
        self.result = {"cipher": selected_cipher, "mode": selected_mode}
        self.destroy()

# Shows the encryption options dialog and returns a dict with cipher mode combo.
def choose_encryption_options():
    popup = EncryptionOptionPopup(root)
    root.wait_window(popup)
    return popup.result

# Performs an undo operation on the text if available.
def do_undo(event=None):
    try:
        text_area.edit_undo()
    except tk.TclError:
        pass

# Performs a redo operation on the text if available.
def do_redo(event=None):
    try:
        text_area.edit_redo()
    except tk.TclError:
        pass

# Prompts for cipher mode combo and password, then saves the editor content as .enc.
def save_encrypted_file():
    options = choose_encryption_options()
    if not options:
        return 

    password_encrypted = None
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
        if password_encrypted is not None:
            _wipe_bytes(password_encrypted)
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
    finally:
        if password_encrypted is not None:
            _wipe_bytes(password_encrypted)

# Basically handles file paths for PyInstaller
def asset_path(filename):
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, filename)

# Saves the editor content as plaintext .txt 
def save_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, 'w', encoding="utf-8") as f:
            f.write(text_area.get(1.0, tk.END))
        text_area.edit_separator()

# Opens a .txt or .enc file; for .enc prompts for password and decrypts.
def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text/Encrypted", "*.txt *.enc"), ("Text files", "*.txt"), ("Encrypted files", "*.enc")])

    if file_path:
        with open(file_path, 'r', encoding="utf-8") as f:
            content = f.read()
        if file_path.endswith('.enc'):
            # Split into header and payload body, header contains cipher mode combo info
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
            password_encrypted = None
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
            except Exception as exc:
                messagebox.showerror("Error", f"Unable to decrypt file: {exc}")
                return
            finally:
                if password_encrypted is not None:
                    _wipe_bytes(password_encrypted)

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

# Creates a new document, optionally prompting to save unsaved changes.
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

# Returns a function that sets a heading/body font size via tags or base font.
def set_text_size(font_size_label):
    def inner():
        global current_text_size
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

# Applies bold styling to selection via a tag or to the base font.
def bold_text():
    if text_area.tag_ranges("sel"):
        start_index = text_area.index("sel.first")
        end_index = text_area.index("sel.last")
        text_area.tag_add("bold", start_index, end_index)
        text_area.tag_configure("bold", font=(text_area.cget("font").split()[0], current_text_size, "bold"))
        text_area.tag_raise("bold")
    else:
        current_font = text_area.cget("font").split()
        font_name = current_font[0]
        text_area.config(font=(font_name, current_text_size, "bold"))

# Applies italic styling to selection via a tag or to the base font.
def italicize_text():
    if text_area.tag_ranges("sel"):
        start_index = text_area.index("sel.first")
        end_index = text_area.index("sel.last")
        text_area.tag_add("italic", start_index, end_index)
        text_area.tag_configure("italic", font=(text_area.cget("font").split()[0], current_text_size, "italic"))
        text_area.tag_raise("italic")
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