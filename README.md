# Crypto Secure Notepad

Tkinter-based Notepad-like editor with prototype encryption and basic formatting.

> WARNING: Current “encryption” logic is experimental and NOT production-secure. Do not store real secrets.

---

## Features

- Plain text editing (New / Open / Save)
- Encrypted save (.enc) with selectable cipher (AES-256, Blowfish, 3DES) and mode (GCM, CBC, ECB)
- Password → key (currently raw SHA-256(password))
- Undo / Redo, Zoom In / Out
- Font sizing (Title, Subtitle, Heading, etc.)
- Bold / Italic (selection or global)
- Keyboard shortcuts (Ctrl+N, Ctrl+O, Ctrl+S, Ctrl+Shift+E, Ctrl+Z/Y, Ctrl+Plus/Minus, Ctrl+B/I)

---

## Project Structure

```
cryptoSecureNotepad/
  notepad.py
  notepad.spec
  images/
    notepadIcon.png
  .gitignore
  README.md
```

---

## Dependencies

- Python 3.10+
- Tkinter (bundled)
- PyCryptodome (`pip install pycryptodome`)
- PyInstaller (for build) (`pip install pyinstaller`)

---

## Running (Source)

```powershell
cd "c:\Users\panda\Personal Files\cryptoSecureNotepad"
python notepad.py
```

---

## Building Executable (PyInstaller)

```powershell
pip install --upgrade pyinstaller
pyinstaller notepad.spec
# EXE: dist\cryptoSecureNotepad\cryptoSecureNotepad.exe
```

---

## Keyboard Shortcuts

| Action            | Shortcut                    |
|-------------------|-----------------------------|
| New File          | Ctrl+N                      |
| Open File         | Ctrl+O                      |
| Save File         | Ctrl+S                      |
| Save Encrypted    | Ctrl+Shift+E                |
| Undo / Redo       | Ctrl+Z / Ctrl+Y             |
| Zoom In / Out     | Ctrl+Plus / Ctrl+Minus      |
| Bold              | Ctrl+B                      |
| Italic            | Ctrl+I                      |

---

## Disclaimer

Educational prototype; not audited. Use at your own risk. Encryption must be refactored for real-world protection.

---
