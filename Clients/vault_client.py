# vault_client.py
import os
import json
import base64
import getpass
import hashlib
from typing import Dict, Any, List
from dataclasses import dataclass, field

import requests
from argon2.low_level import hash_secret, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MFA_BASE = "https://localhost:4443"
VERIFY_CERT = "certs/server.crt"  # trust server certificate

VAULT_PATH = "vault.json.enc"
META_PATH = "vault.meta.json"
INTEGRITY_PATH = "vault.integrity.sha256"

ARGON2_PARAMS = {
    "time_cost": 3,
    "memory_cost": 64_000,
    "parallelism": 2,
    "hash_len": 32,  # we will still enforce 32 bytes downstream
    "type": Type.ID
}

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

def _ensure_aes_key_length(key: bytes) -> bytes:
    """
    Ensure key size is compatible with AES-GCM: 16, 24, or 32 bytes.
    Prefer 32 bytes (AES-256). If longer, truncate; if shorter, pad with zeros (rare).
    """
    if len(key) >= 32:
        return key[:32]
    elif len(key) >= 24:
        return key[:24]
    elif len(key) >= 16:
        return key[:16]
    else:
        # pad to 16 bytes (shouldn't happen with Argon2 unless misconfigured)
        return (key + b"\x00" * (16 - len(key)))[:16]

def derive_key_argon2id(master_password: str, salt: bytes) -> bytes:
    if not master_password:
        raise ValueError("Master Password cannot be empty.")
    raw = hash_secret(
        master_password.encode(),
        salt,
        ARGON2_PARAMS["time_cost"],
        ARGON2_PARAMS["memory_cost"],
        ARGON2_PARAMS["parallelism"],
        ARGON2_PARAMS["hash_len"],
        ARGON2_PARAMS["type"]
    )
    key = _ensure_aes_key_length(raw)
    # Sanity check
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Derived AES key has invalid length: {len(key)} bytes.")
    return key

def save_integrity(cipher_text: bytes):
    digest = hashlib.sha256(cipher_text).hexdigest()
    with open(INTEGRITY_PATH, "w") as f:
        f.write(digest)

def check_integrity(cipher_text: bytes) -> bool:
    if not os.path.exists(INTEGRITY_PATH):
        return False
    with open(INTEGRITY_PATH, "r") as f:
        stored = f.read().strip()
    current = hashlib.sha256(cipher_text).hexdigest()
    return stored == current

def encrypt_vault(vault: Vault, key: bytes) -> bytes:
    # Extra guard to catch environment-specific issues early
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AESGCM key must be 128, 192, or 256 bits; got {len(key)} bytes.")
    aes = AESGCM(key)
    nonce = os.urandom(12)
    plain = json.dumps(vault.to_dict()).encode()
    ct = aes.encrypt(nonce, plain, associated_data=None)
    return nonce + ct  # prepend nonce

def decrypt_vault(cipher_blob: bytes, key: bytes) -> Vault:
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AESGCM key must be 128, 192, or 256 bits; got {len(key)} bytes.")
    aes = AESGCM(key)
    nonce = cipher_blob[:12]
    ct = cipher_blob[12:]
    plain = aes.decrypt(nonce, ct, associated_data=None)
    return Vault.from_dict(json.loads(plain.decode()))

def initialize_vault(master_password: str):
    if not master_password:
        raise ValueError("Master Password cannot be empty.")
    # Create salt and derive key
    salt = os.urandom(16)
    key = derive_key_argon2id(master_password, salt)
    vault = Vault(entries=[])
    cipher_blob = encrypt_vault(vault, key)
    with open(VAULT_PATH, "wb") as f:
        f.write(cipher_blob)
    with open(META_PATH, "w") as f:
        meta = {
            "salt_b64": base64.b64encode(salt).decode(),
            "argon2_params": {
                "time_cost": ARGON2_PARAMS["time_cost"],
                "memory_cost": ARGON2_PARAMS["memory_cost"],
                "parallelism": ARGON2_PARAMS["parallelism"],
                "hash_len": ARGON2_PARAMS["hash_len"],
                "type": "argon2id"
            },
            "version": 1
        }
        json.dump(meta, f, indent=2)
    save_integrity(cipher_blob)
    print("Vault initialized and encrypted locally with client-side key derivation.")

def load_key(master_password: str) -> bytes:
    if not os.path.exists(META_PATH):
        raise FileNotFoundError("Vault metadata not found. Initialize the vault first.")
    with open(META_PATH, "r") as f:
        meta = json.load(f)
    salt = base64.b64decode(meta["salt_b64"])
    key = derive_key_argon2id(master_password, salt)
    return key

def add_entry(master_password: str, entry: VaultEntry):
    key = load_key(master_password)
    with open(VAULT_PATH, "rb") as f:
        cipher_blob = f.read()
    if not check_integrity(cipher_blob):
        raise RuntimeError("Vault integrity check failed. Possible tampering detected.")
    vault = decrypt_vault(cipher_blob, key)
    vault.entries.append(entry)
    new_blob = encrypt_vault(vault, key)
    with open(VAULT_PATH, "wb") as f:
        f.write(new_blob)
    save_integrity(new_blob)
    print("Entry added and vault re-encrypted.")

def list_entries(master_password: str):
    key = load_key(master_password)
    with open(VAULT_PATH, "rb") as f:
        cipher_blob = f.read()
    if not check_integrity(cipher_blob):
        raise RuntimeError("Vault integrity check failed.")
    vault = decrypt_vault(cipher_blob, key)
    for i, e in enumerate(vault.entries):
        print(f"[{i}] {e.name} | {e.username} | {e.url}")

def edit_entry(master_password: str, idx: int, updates: Dict[str, str]):
    key = load_key(master_password)
    with open(VAULT_PATH, "rb") as f:
        cipher_blob = f.read()
    if not check_integrity(cipher_blob):
        raise RuntimeError("Vault integrity check failed.")
    vault = decrypt_vault(cipher_blob, key)
    if idx < 0 or idx >= len(vault.entries):
        raise IndexError("Invalid entry index.")
    entry = vault.entries[idx]
    for k, v in updates.items():
        if hasattr(entry, k):
            setattr(entry, k, v)
    new_blob = encrypt_vault(vault, key)
    with open(VAULT_PATH, "wb") as f:
        f.write(new_blob)
    save_integrity(new_blob)
    print("Entry edited and vault re-encrypted.")

def mfa_get_otp(username: str, device_id: str, device_key: str) -> str:
    r = requests.post(f"{MFA_BASE}/otp/current",
                      json={"username": username, "device_id": device_id, "device_key": device_key},
                      verify=VERIFY_CERT)
    r.raise_for_status()
    data = r.json()
    print(f"Server OTP valid_for_seconds={data['valid_for_seconds']}")
    return data["otp"]

def mfa_login(username: str, master_password: str, otp: str, device_id: str, device_key: str) -> Dict[str, Any]:
    r = requests.post(f"{MFA_BASE}/auth/login",
                      json={
                          "username": username,
                          "master_password": master_password,
                          "otp": otp,
                          "device_id": device_id,
                          "device_key": device_key
                      },
                      verify=VERIFY_CERT)
    r.raise_for_status()
    return r.json()

def main():
    print("VaultGuard CLI")
    print("1) Initialize vault")
    print("2) List entries (requires login)")
    print("3) Add entry (requires login)")
    print("4) Edit entry (requires login)")
    choice = input("Select option: ").strip()

    username = input("Username (for MFA server): ").strip()
    device_id = input("Device ID: ").strip()
    device_key = getpass.getpass("Device Key: ").strip()

    if choice == "1":
        master_password = getpass.getpass("Create Master Password: ").strip()
        if not master_password:
            print("Master Password cannot be empty.")
            return
        # Client-side vault initialization
        try:
            initialize_vault(master_password)
        except Exception as e:
            print("Initialization error:", e)
            return
        print("Enroll user on MFA server now to link TOTP and MPW...")
        enroll = input("Enroll now? [y/n]: ").strip().lower()
        if enroll == "y":
            try:
                r = requests.post(f"{MFA_BASE}/user/enroll",
                                  json={"username": username, "master_password": master_password},
                                  verify=VERIFY_CERT)
                if r.status_code == 200:
                    j = r.json()
                    print("Enrolled. TOTP provisioning URI (optional):")
                    print(j.get("provisioning_uri", "<none>"))
                else:
                    print("Enrollment failed:", r.text)
            except Exception as e:
                print("Enrollment error:", e)
        return

    # For read/write operations: require MFA login flow (MPW + OTP)
    master_password = getpass.getpass("Master Password: ").strip()
    if not master_password:
        print("Master Password cannot be empty.")
        return
    try:
        otp = mfa_get_otp(username, device_id, device_key)
        auth = mfa_login(username, master_password, otp, device_id, device_key)
        print("Login OK. Token:", auth["token"])
    except Exception as e:
        print("Login/MFA error:", e)
        return

    if choice == "2":
        try:
            list_entries(master_password)
        except Exception as e:
            print("List error:", e)
    elif choice == "3":
        name = input("Entry name: ").strip()
        uname = input("Username: ").strip()
        pw = getpass.getpass("Password: ").strip()
        url = input("URL (optional): ").strip()
        notes = input("Notes (optional): ").strip()
        try:
            add_entry(master_password, VaultEntry(name=name, username=uname, password=pw, url=url, notes=notes))
        except Exception as e:
            print("Add error:", e)
    elif choice == "4":
        try:
            idx = int(input("Entry index: ").strip())
        except ValueError:
            print("Invalid index.")
            return
        print("Leave field empty to keep unchanged.")
        fields = {}
        for field in ["name", "username", "password", "url", "notes"]:
            val = input(f"{field}: ").strip()
            if val:
                fields[field] = val
        try:
            edit_entry(master_password, idx, fields)
        except Exception as e:
            print("Edit error:", e)
    else:
        print("Unknown choice.")

if __name__ == "__main__":
    main()
