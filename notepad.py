import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import os, sys

root = tk.Tk()
root.title("notepad")

text_area = tk.Text(root, wrap='word', font=("Arial", 12), undo=True, autoseparators=True, maxundo=-1)
text_area.pack(expand=True, fill='both')

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
        ciphers = ["AES-256", "Blowfish", "3DES"]
        for i, cipher in enumerate(ciphers):
            ttk.Radiobutton(frm, text=cipher, variable=self.cipher_var, value=cipher).grid(row=i+1, column=0, sticky="w")
        
        ttk.Label(frm, text="Mode").grid(row=0, column=1, sticky="w", padx=(20,0))
        modes = ["GCM", "CBC", "ECB"]
        for i, mode in enumerate(modes):
            ttk.Radiobutton(frm, text=mode, variable=self.mode_var, value=mode).grid(row=i+1, column=1, sticky="w", padx=(20,0))

        btns = ttk.Frame(frm)
        btns.grid(row=4, column = 0, columnspan=2, pady=(12,0), sticky="e")
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
        messagebox.showinfo("Selected Encryption Options", f"You selected: {selected_cipher} with {selected_mode}")
        self.result = {"cipher": selected_cipher, "mode": selected_mode}
        self.destroy()

def choose_encryption_options():
    popup = EncryptionOptionPopup(root)
    root.wait_window(popup)
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

    file_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                             filetypes=[("Encrypted files", "*.enc")])
    
    if not file_path:
        return

    data = text_area.get("1.0", "end-1c")

    try:
        with open(file_path, 'w', encoding="utf-8") as f:
            f.write(f"CIPHER={options['cipher']}|MODE={options['mode']}\n")
            f.write(data)
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
            cipher = content.split('CIPHER=')[1].split('|')[0]
            mode = content.split('MODE=')[1].split('\n')[0]
            content = '\n'.join(content.split('\n')[1:])
            messagebox.showinfo("Encrypted File", f"File is encrypted with options: {cipher}, {mode}")
            
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


root.event_add('<<ZoomIn>>',
               '<Control-plus>',      
               '<Control-Shift-=>',    
               '<Control-=>',
               '<Control-KP_Add>')   
root.bind_all('<<ZoomIn>>', lambda event: zoom_in())
root.bind('<Control-minus>', lambda event: zoom_out())
root.bind('<Control-z>', lambda event: text_area.edit_undo())
root.bind('<Control-y>', lambda event: text_area.edit_redo())

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
file_menu.add_command(label="Open", command=open_file)
file_menu.add_command(label="Save", command=save_file)
file_menu.add_command(label="Save Encrypted", command=save_encrypted_file)
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

root.config(menu=menu_bar)
root.mainloop()