#!/usr/bin/env python3
"""
cofre.py - locks (encrypts) and unlocks the files on a USB drive with a password.

Put this file in the root of the USB drive and run it from Command Prompt:

    python cofre.py create     -> set the password (first time only)
    python cofre.py lock       -> encrypt every file on the drive
    python cofre.py unlock     -> decrypt everything back

Optional: --folder E:\\   (to lock/unlock another folder or drive)

Requires:  pip install cryptography

How it works:
  - Your password becomes a 256-bit key via scrypt (slow on purpose,
    to make brute-force attacks harder).
  - Each file is encrypted with AES-256-GCM, using its own key.
  - The original name and folder are encrypted too; only files with
    random names ending in .cofre are left on the drive.
  - GCM detects a wrong password and tampered/corrupted files.

WARNING: if you forget the password, the files CANNOT be recovered.
"""
import argparse
import base64
import getpass
import json
import os
import secrets
import struct
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    sys.exit("Missing the 'cryptography' library. Install it with:  pip install cryptography")

MAGIC = b"COFRE1\0\0"          # 8 bytes that identify the format
SALT_LEN = 16
HEADER_LEN = len(MAGIC) + SALT_LEN
CHUNK = 1024 * 1024            # encrypt in 1 MB blocks (handles large files)
CONFIG = "cofre.json"
EXT = ".cofre"
SCRYPT_N = 2 ** 17             # ~128 MB of RAM, ~0.5 s per password attempt
IGNORED_DIRS = {"System Volume Information", "$RECYCLE.BIN"}


# ---------------------------------------------------------------- keys

def derive_master(password: str, salt: bytes, n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(password.encode("utf-8"))


def subkey(master: bytes, salt: bytes, usage: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=usage).derive(master)


def nonce(i: int) -> bytes:
    # each file has a unique key, so a counter as the nonce is safe
    return struct.pack(">IQ", 0, i)


def aad(header: bytes, i: int, final: int) -> bytes:
    # binds each block to its position and marks the last one:
    # prevents reordering, removing or truncating blocks undetected
    return header + struct.pack(">QB", i, final)


# ---------------------------------------------------------------- files

def encrypt_file(source: Path, dest: Path, master: bytes, relpath: str) -> None:
    salt = secrets.token_bytes(SALT_LEN)
    header = MAGIC + salt
    aes = AESGCM(subkey(master, salt, b"cofre-arquivo"))
    i = 0
    with open(source, "rb") as fin, open(dest, "wb") as fout:
        fout.write(header)

        def write(data: bytes, final: int) -> None:
            nonlocal i
            ct = aes.encrypt(nonce(i), data, aad(header, i, final))
            fout.write(struct.pack(">I", len(ct)))
            fout.write(ct)
            i += 1

        write(relpath.encode("utf-8"), 0)            # block 0 = original name/folder
        current = fin.read(CHUNK)
        while True:
            nxt = fin.read(CHUNK)
            write(current, 0 if nxt else 1)
            if not nxt:
                break
            current = nxt
        fout.flush()
        os.fsync(fout.fileno())


def decrypt_file(path: Path, master: bytes, out_base: Path | None) -> str:
    """Decrypts `path`. If out_base is None, only verifies.
    Returns the original relative path."""
    tmp = None
    fout = None
    try:
        with open(path, "rb") as f:
            header = f.read(HEADER_LEN)
            if len(header) != HEADER_LEN or not header.startswith(MAGIC):
                raise ValueError("not a vault file")
            aes = AESGCM(subkey(master, header[len(MAGIC):], b"cofre-arquivo"))
            i, relpath = 0, None
            while True:
                size_b = f.read(4)
                if len(size_b) < 4:
                    raise ValueError("file truncated/corrupted")
                (size,) = struct.unpack(">I", size_b)
                ct = f.read(size)
                if len(ct) != size:
                    raise ValueError("file truncated/corrupted")
                final = 0
                try:
                    data = aes.decrypt(nonce(i), ct, aad(header, i, 0))
                except InvalidTag:
                    if i == 0:
                        raise ValueError("wrong password or tampered file")
                    try:
                        data = aes.decrypt(nonce(i), ct, aad(header, i, 1))
                        final = 1
                    except InvalidTag:
                        raise ValueError("tampered/corrupted file")

                if i == 0:
                    relpath = data.decode("utf-8")
                    if out_base is not None:
                        target = safe_path(out_base, relpath)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        tmp = target.with_name(target.name + ".restoring")
                        fout = open(tmp, "wb")
                elif fout is not None:
                    fout.write(data)
                i += 1
                if final:
                    if f.read(1):
                        raise ValueError("extra data after end")
                    break
        if fout is not None:
            fout.close()
            fout = None
            target = free_name(safe_path(out_base, relpath))
            os.replace(tmp, target)
            tmp = None
        return relpath
    finally:
        if fout is not None:
            fout.close()
        if tmp is not None and tmp.exists():
            tmp.unlink()


def safe_path(base: Path, relpath: str) -> Path:
    target = (base / relpath).resolve()
    if base.resolve() not in target.parents:
        raise ValueError(f"suspicious path: {relpath}")
    return target


def free_name(target: Path) -> Path:
    if not target.exists():
        return target
    n = 1
    while True:
        cand = target.with_name(f"{target.stem} (restored {n}){target.suffix}")
        if not cand.exists():
            return cand
        n += 1


# ---------------------------------------------------------------- config / password

def own_files() -> set[Path]:
    s = {Path(__file__).resolve()}
    if getattr(sys, "frozen", False):        # if turned into an .exe with PyInstaller
        s.add(Path(sys.executable).resolve())
    return s


def load_master(folder: Path) -> bytes:
    cfg_path = folder / CONFIG
    if not cfg_path.exists():
        sys.exit(f"No vault here. Run first:  python {Path(__file__).name} create")
    cfg = json.loads(cfg_path.read_text("utf-8"))
    salt = base64.b64decode(cfg["salt"])
    verifier = base64.b64decode(cfg["verificador"])
    password = getpass.getpass("Password: ")
    print("Checking password...")
    master = derive_master(password, salt, cfg["n"])
    try:
        AESGCM(subkey(master, salt, b"cofre-verifica")).decrypt(nonce(0), verifier, None)
    except InvalidTag:
        sys.exit("Wrong password.")
    return master


def cmd_create(folder: Path) -> None:
    cfg_path = folder / CONFIG
    if cfg_path.exists():
        sys.exit("A vault already exists here (cofre.json). Nothing was changed.")
    password = getpass.getpass("New password (minimum 8 characters): ")
    if len(password) < 8:
        sys.exit("Password too short.")
    if getpass.getpass("Repeat the password: ") != password:
        sys.exit("The passwords do not match.")
    salt = secrets.token_bytes(SALT_LEN)
    master = derive_master(password, salt, SCRYPT_N)
    verifier = AESGCM(subkey(master, salt, b"cofre-verifica")).encrypt(nonce(0), b"cofre-ok", None)
    cfg = {"versao": 1, "n": SCRYPT_N,
           "salt": base64.b64encode(salt).decode(),
           "verificador": base64.b64encode(verifier).decode()}
    cfg_path.write_text(json.dumps(cfg, indent=2), "utf-8")
    print("Vault created. Now run:  python cofre.py lock")
    print("Remember: without the password, the files cannot be recovered.")


def list_files(folder: Path, want_vault: bool) -> list[Path]:
    skip = own_files() | {(folder / CONFIG).resolve()}
    found = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for name in files:
            p = Path(root) / name
            if p.resolve() in skip or name.endswith((".tmp", ".restoring")):
                continue
            if name.endswith(EXT) == want_vault:
                found.append(p)
    return found


def remove_empty_dirs(folder: Path) -> None:
    for root, dirs, files in os.walk(folder, topdown=False):
        r = Path(root)
        if r != folder and r.name not in IGNORED_DIRS and not any(r.iterdir()):
            r.rmdir()


def cmd_lock(folder: Path) -> None:
    files = list_files(folder, want_vault=False)
    if not files:
        print("Nothing to lock.")
        return
    master = load_master(folder)
    ok = fails = 0
    for file in files:
        rel = file.relative_to(folder).as_posix()
        dest = folder / (secrets.token_hex(8) + EXT)
        tmp = dest.with_suffix(".tmp")
        try:
            encrypt_file(file, tmp, master, rel)
            decrypt_file(tmp, master, None)        # verify before deleting the original
            os.replace(tmp, dest)
            file.unlink()
            ok += 1
            print(f"  locked: {rel}")
        except Exception as e:
            fails += 1
            if tmp.exists():
                tmp.unlink()
            print(f"  FAILED: {rel} ({e}) - original kept")
    remove_empty_dirs(folder)
    print(f"\n{ok} file(s) locked, {fails} failure(s).")


def cmd_unlock(folder: Path) -> None:
    files = list_files(folder, want_vault=True)
    if not files:
        print("Nothing to unlock.")
        return
    master = load_master(folder)
    ok = fails = 0
    for file in files:
        try:
            rel = decrypt_file(file, master, folder)
            file.unlink()
            ok += 1
            print(f"  unlocked: {rel}")
        except Exception as e:
            fails += 1
            print(f"  FAILED: {file.name} ({e}) - encrypted file kept")
    print(f"\n{ok} file(s) unlocked, {fails} failure(s).")


def main() -> None:
    ap = argparse.ArgumentParser(description="Password vault for a USB drive.")
    ap.add_argument("command", choices=["create", "lock", "unlock"])
    ap.add_argument("--folder", help="target folder or drive (default: where the script is)")
    a = ap.parse_args()
    folder = Path(a.folder).resolve() if a.folder else Path(__file__).resolve().parent
    {"create": cmd_create, "lock": cmd_lock, "unlock": cmd_unlock}[a.command](folder)


if __name__ == "__main__":
    main()
