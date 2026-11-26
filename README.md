# 🔒 USB Vault — password for the files on your USB drive

A **Python** script that encrypts every file on a USB drive with a
**password**. Without the password, anyone who opens the drive sees only `.cofre`
files with random names and unreadable content — neither the original names nor
folders are visible.

Built for **Windows 11 Home** (also works on Linux/macOS), with no need for
BitLocker.

---

##  How it works

- **Lock:** encrypts every file on the USB drive.
- **Unlock:** decrypts everything back, with the original names and folders.
- Protects the **content**, the **name** and the **folder** of each file.
- Warns when the password is wrong or the file was corrupted.

---

##  How it works (under the hood)

- Your password goes through **scrypt**, which turns it into a 256-bit key.
  scrypt is slow on purpose, to make brute-force attacks harder.
- Each file is encrypted with **AES-256-GCM**, using its own key.
- The original name and folder are stored **inside** the encrypted file,
  also encrypted. Only `.cofre` files with random names are left on the drive.
- GCM detects a wrong password and any tampering with the file.
- Before deleting the original, the script checks that the encrypted version
  opens correctly — so you don't lose a file to an error along the way.

---

##  How to use

### 1. Install Python
Download it from [python.org](https://www.python.org/downloads/) and, during
installation, check **"Add Python to PATH"**.

### 2. Install the required library
Open Command Prompt and run:
```bash
pip install cryptography
```

### 3. Put the script on the USB drive
Copy the **cofre.py** file to the root of the drive (e.g. `E:\`).

### 4. Use the commands
In Command Prompt, switch to the drive (e.g. type `E:` and Enter) and run:

```bash
python cofre.py criar      # set the password (first time only)
python cofre.py trancar    # encrypt every file on the drive
python cofre.py abrir      # decrypt everything back
```

Optional — lock/unlock another folder or drive:
```bash
python cofre.py trancar --pasta E:\
```

---

## ⚠️ Important warnings

- **If you forget the password, there is no way to recover the files.** There is
  no "password recovery".
- On a USB drive (flash memory), a deleted original file can sometimes be
  recovered with forensic tools. For very sensitive data, start with the drive
  already locked and only add new files, locking again afterwards.
- To open it on another computer, it also needs Python and the `cryptography`
  library.

---

##  Technologies

- Python 3
- [cryptography](https://cryptography.io/) — AES-256-GCM, scrypt, HKDF

---
