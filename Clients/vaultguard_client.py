#!/usr/bin/env python3
import json
import os
import base64
import getpass
import hashlib
from typing import Dict, Any, List
from dataclasses import dataclass, field

import requests
from argon2.low_level import hash_secret, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuration ---
SERVER_URL = "https://127.0.0.1:4443"
VERIFY_CERT = False  # For self-signed certificate, dev only

VAULT_PATH = "vault.json.enc"
META_PATH = "vault.meta.json"
INTEGRITY_PATH = "vault.integrity.sha256"

ARGON2_PARAMS = {
    "time_cost": 3,
    "memory_cost": 64_000,
    "parallelism": 2,
    "hash_len": 32,
    "type": Type.ID
}

# --- Data models ---
@dataclass
class VaultEntry:
    name: str
    username: str
    password: str
    url: str = ""
    notes: str = ""

@dataclass
class Vault:
    entries: List[VaultEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"entries": [vars(e) for e in self.entries]}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Vault":
        return Vault(entries=[VaultEntry(**e) for e in d.get("entries", [])])

# --- Crypto helpers ---
def _ensure_aes_key_length(key: bytes) -> bytes:
    if len(key) >= 32:
        return key[:32]
    elif len(key) >= 24:
        return key[:24]
    elif len(key) >= 16:
        return key[:16]
    else:
        return (key + b"\x00" * (16 - len(key)))[:16]

def derive_key_argon2id(master_password: str, salt: bytes) -> bytes:
    raw = hash_secret(
        master_password.encode(),
        salt,
        ARGON2_PARAMS["time_cost"],
        ARGON2_PARAMS["memory_cost"],
        ARGON2_PARAMS["parallelism"],
        ARGON2_PARAMS["hash_len"],
        ARGON2_PARAMS["type"]
    )
    return _ensure_aes_key_length(raw)

def save_integrity(cipher_text: bytes):
    digest = hashlib.sha256(cipher_text).hexdigest()
    with open(INTEGRITY_PATH, "w") as f:
        f.write(digest)

def check_integrity(cipher_text: bytes) -> bool:
    if not os.path.exists(INTEGRITY_PATH):
        return False
    with open(INTEGRITY_PATH, "r") as f:
        stored = f.read().strip()
    return hashlib.sha256(cipher_text).hexdigest() == stored

def encrypt_vault(vault: Vault, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, json.dumps(vault.to_dict()).encode(), None)
    return nonce + ct

def decrypt_vault(cipher_blob: bytes, key: bytes) -> Vault:
    aes = AESGCM(key)
    nonce = cipher_blob[:12]
    ct = cipher_blob[12:]
    plain = aes.decrypt(nonce, ct, None)
    return Vault.from_dict(json.loads(plain.decode()))

# --- Vault lifecycle ---
def initialize_vault(master_password: str):
    salt = os.urandom(16)
    key = derive_key_argon2id(master_password, salt)
    vault = Vault()
    blob = encrypt_vault(vault, key)
    with open(VAULT_PATH, "wb") as f:
        f.write(blob)
    meta = {
        "salt_b64": base64.b64encode(salt).decode(),
        "argon2_params": {
            "time_cost": ARGON2_PARAMS["time_cost"],
            "memory_cost": ARGON2_PARAMS["memory_cost"],
            "parallelism": ARGON2_PARAMS["parallelism"],
            "hash_len": ARGON2_PARAMS["hash_len"],
            "type": "argon2id"  # store as string
        }
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    save_integrity(blob)
    print("[+] Vault initialized locally.")

def load_key(master_password: str) -> bytes:
    with open(META_PATH, "r") as f:
        meta = json.load(f)
    salt = base64.b64decode(meta["salt_b64"])
    return derive_key_argon2id(master_password, salt)

def add_entry(master_password: str, entry: VaultEntry):
    key = load_key(master_password)
    with open(VAULT_PATH, "rb") as f:
        blob = f.read()
    if not check_integrity(blob):
        raise RuntimeError("Vault integrity failed!")
    vault = decrypt_vault(blob, key)
    vault.entries.append(entry)
    new_blob = encrypt_vault(vault, key)
    with open(VAULT_PATH, "wb") as f:
        f.write(new_blob)
    save_integrity(new_blob)
    print("[+] Entry added.")

def list_entries(master_password: str):
    key = load_key(master_password)
    with open(VAULT_PATH, "rb") as f:
        blob = f.read()
    if not check_integrity(blob):
        raise RuntimeError("Vault integrity failed!")
    vault = decrypt_vault(blob, key)
    for i, e in enumerate(vault.entries):
        print(f"[{i}] {e.name} | {e.username} | {e.url}")

def edit_entry(master_password: str, idx: int, updates: Dict[str, str]):
    key = load_key(master_password)
    with open(VAULT_PATH, "rb") as f:
        blob = f.read()
    if not check_integrity(blob):
        raise RuntimeError("Vault integrity failed!")
    vault = decrypt_vault(blob, key)
    if idx < 0 or idx >= len(vault.entries):
        raise IndexError("Invalid index")
    for k, v in updates.items():
        if hasattr(vault.entries[idx], k):
            setattr(vault.entries[idx], k, v)
    new_blob = encrypt_vault(vault, key)
    with open(VAULT_PATH, "wb") as f:
        f.write(new_blob)
    save_integrity(new_blob)
    print("[+] Entry edited.")

# --- Server communication ---
def client_register(username: str, password: str) -> bool:
    try:
        r = requests.post(SERVER_URL, data=f"reg:{username}:{password}", verify=VERIFY_CERT)
        return "res:regok" in r.text
    except:
        return False

def client_login(username: str, password: str) -> bool:
    try:
        r = requests.post(SERVER_URL, data=f"log:{username}:{password}", verify=VERIFY_CERT)
        return "res:logok" in r.text
    except:
        return False

# --- CLI ---
def main():
    print("VaultGuard CLI — Server login only")
    print("1) Initialize vault")
    print("2) Register on server")
    print("3) List entries")
    print("4) Add entry")
    print("5) Edit entry")
    print("6) Exit")
    choice = input("Select option: ").strip()

    if choice == "1":
        mpw = getpass.getpass("Create Master Password: ").strip()
        if mpw:
            initialize_vault(mpw)
        return

    if choice == "2":
        u = input("New username: ").strip()
        p = getpass.getpass("New password: ").strip()
        if client_register(u, p):
            print("[+] Registration successful")
        else:
            print("[!] Registration failed")
        return

    if choice in ("3", "4", "5"):
        u = input("Server username: ").strip()
        p = getpass.getpass("Server password: ").strip()
        if not client_login(u, p):
            print("[!] Server login failed")
            return

        mpw = getpass.getpass("Master Password (for vault): ").strip()
        if choice == "3":
            list_entries(mpw)
        elif choice == "4":
            name = input("Entry name: ").strip()
            uname = input("Username: ").strip()
            pw = getpass.getpass("Password: ").strip()
            url = input("URL: ").strip()
            notes = input("Notes: ").strip()
            add_entry(mpw, VaultEntry(name=name, username=uname, password=pw, url=url, notes=notes))
        elif choice == "5":
            idx = int(input("Entry index: ").strip())
            updates = {}
            for field in ["name", "username", "password", "url", "notes"]:
                val = input(f"{field}: ").strip()
                if val:
                    updates[field] = val
            edit_entry(mpw, idx, updates)

if __name__ == "__main__":
    main()
