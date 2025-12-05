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

## How to Run Crypto Secure Notepad

### Prerequisites
- Python 3.10+ installed
- pip available in your PATH

Optional (for packaging to an .exe/.app/.bin):
- PyInstaller

### Build a standalone executable (Windows/macOS/Linux)
1) Download repository zip file
- Extract folder (secureNotepad-main)
- Open folder (secureNotepad-main) in command line

2) Install PyInstaller
```bash
pip install --upgrade pyinstaller
```

3) Build using the provided spec
```bash
pyinstaller notepad.spec
```

4) Run the built binary
- Windows: `dist/cryptoSecureNotepad/cryptoSecureNotepad.exe`
- macOS: `dist/cryptoSecureNotepad/cryptoSecureNotepad` (may need: `chmod +x` and Gatekeeper approval)
- Linux: `dist/cryptoSecureNotepad/cryptoSecureNotepad` (`chmod +x` if needed)

### Using the app

- Open: File → Open (supports .txt and .enc)
- Save: File → Save (plaintext .txt)
- Save Encrypted: File → Save Encrypted
  - Pick a cipher/mode in the popup (placeholders available)
  - Enter a password when prompted
- Undo/Redo: Ctrl+Z / Ctrl+Y
- Zoom: Ctrl+Plus / Ctrl+Minus
- Optional formatting: Bold/Italic and size tags via menu/shortcuts

Note: The current encryption is a learning prototype and not production-secure. Do not store sensitive data.

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
