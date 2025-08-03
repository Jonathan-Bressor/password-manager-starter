
# 🔐 Simple Password Manager (Starter)

A beginner-friendly password manager using Python and the `cryptography` library.  
It derives an encryption key from a **master password** (PBKDF2-HMAC) and stores encrypted credentials locally in `vault.json`.

> **Learning project only.** Do **not** use this to store real credentials.

## Features
- Master-password protected vault
- AES-based encryption via `cryptography.Fernet`
- Store, retrieve, and list credentials via a simple CLI
- Proper key derivation with PBKDF2-HMAC and a per-vault salt

## Requirements
- Python 3.8+
- `cryptography`

## Setup
```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run
```bash
python main.py
```
Use the **same master password** to reopen your existing vault. If you enter a different master password, decryption will fail when retrieving entries.

## Commands
- **Add credential**: Save a site/service, username, and password (encrypted).
- **Retrieve credential**: Decrypt and display the stored password for a site.
- **List all sites**: Show the set of sites stored in the vault.

## Project Structure
```
password-manager-starter/
├── main.py
├── password_manager.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Security Notes
- This is a minimal, educational codebase. Real password managers require much more:
  - Secret handling/clipboard hygiene
  - Secure UI/UX and safe defaults
  - Tamper detection / integrity protection (HMAC on vault file)
  - Defense against offline brute-force (tunable KDF parameters, lockouts)
  - Secret sharing/recovery and backups
- Treat the vault file as sensitive. Anyone with it can attempt offline cracking of your master password.

## License
MIT
