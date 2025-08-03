
import base64
import json
import os
from dataclasses import dataclass
from typing import Dict, Any

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

VAULT_FILE = "vault.json"
KDF_ITERATIONS = 200_000  # tune higher for more security


@dataclass
class Vault:
    salt: bytes
    data: Dict[str, Dict[str, str]]  # site -> {username, password (encrypted)}

    @staticmethod
    def empty(salt: bytes) -> "Vault":
        return Vault(salt=salt, data={})

    def to_json(self) -> Dict[str, Any]:
        return {
            "salt": base64.urlsafe_b64encode(self.salt).decode(),
            "data": self.data,
        }

    @staticmethod
    def from_json(obj: Dict[str, Any]) -> "Vault":
        salt = base64.urlsafe_b64decode(obj["salt"].encode())
        data = obj.get("data", {})
        return Vault(salt=salt, data=data)


def _ensure_vault_exists() -> None:
    if not os.path.exists(VAULT_FILE):
        salt = os.urandom(16)
        vault = Vault.empty(salt)
        _save_vault(vault)


def _load_vault() -> Vault:
    _ensure_vault_exists()
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        obj = json.load(f)
    return Vault.from_json(obj)


def _save_vault(vault: Vault) -> None:
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(vault.to_json(), f, indent=2)


def _derive_key(master_password: str, salt: bytes) -> bytes:
    # Derive a 32-byte key suitable for Fernet (base64 urlsafe-encoded)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def get_fernet(master_password: str) -> Fernet:
    vault = _load_vault()
    key = _derive_key(master_password, vault.salt)
    return Fernet(key)


def add_credential(master_password: str, site: str, username: str, password: str) -> None:
    site = site.strip()
    if not site:
        print("[-] Site name cannot be empty.")
        return

    vault = _load_vault()
    f = Fernet(_derive_key(master_password, vault.salt))
    token = f.encrypt(password.encode("utf-8")).decode("utf-8")
    vault.data[site] = {"username": username, "password": token}
    _save_vault(vault)
    print(f"[+] Saved credentials for '{site}'.")


def get_credential(master_password: str, site: str) -> None:
    vault = _load_vault()
    if site not in vault.data:
        print("[-] No credentials for that site.")
        return

    entry = vault.data[site]
    f = Fernet(_derive_key(master_password, vault.salt))
    try:
        decrypted = f.decrypt(entry["password"].encode("utf-8")).decode("utf-8")
    except InvalidToken:
        print("[-] Failed to decrypt. Is the master password correct?")
        return

    print(f"Site: {site}\nUsername: {entry['username']}\nPassword: {decrypted}")


def list_sites() -> None:
    vault = _load_vault()
    if not vault.data:
        print("Vault is empty.")
        return
    print("Stored sites:")
    for site in sorted(vault.data.keys()):
        print(f" - {site}")
