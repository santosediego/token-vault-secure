#!/usr/bin/env python3
"""
token_vault_secure.py

Menu interactive vault (Model B improved)
- Vault file encrypted with GPG symmetric AES256 (passphrase you enter)
- Each entry encrypted with AES-GCM using a key derived from (dica1_value + '|' + dica2_value)
  - Argon2id used if available, else PBKDF2-HMAC-SHA256 fallback
- Menu: add / get / list / delete / backup / exit
- Auto-generate strong dica values if you press Enter
- Keeps up to 5 backups of vault.gpg

Usage:
  python3 token_vault_secure.py
"""

import os
import sys
import json
import base64
import binascii
import secrets
import getpass
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime, timezone

# crypto libs (required)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except Exception:
    print("ERRO: instale 'cryptography' (pip install cryptography)")
    sys.exit(1)

# argon2 optional (preferred)
USE_ARGON2 = False
try:
    from argon2.low_level import hash_secret_raw, Type
    USE_ARGON2 = True
except Exception:
    USE_ARGON2 = False

# clipboard optional
HAVE_CLIP = False
try:
    import pyperclip
    HAVE_CLIP = True
except Exception:
    HAVE_CLIP = False

# ---------------- CONFIG ----------------
HOME = Path.home()
VAULT_DIR = HOME / ".vault"
VAULT_PATH = VAULT_DIR / "vault.gpg"
GPG_BIN = "gpg"

SALT_LEN = 16       # bytes
NONCE_LEN = 12      # AES-GCM recommended
DERIVED_KEY_LEN = 32  # bytes for AES-256
ARGON2_TIME = 2
ARGON2_MEM = 65536  # KiB (64 MiB)
ARGON2_PAR = 1
PBKDF2_ITERS = 250_000

BACKUP_KEEP = 5     # keep last 5 backups

# length of auto-generated dica tokens (configurable)
AUTO_DICA_LEN = 24   # characters (base62-ish)

# ---------------- helpers ----------------
def ensure_vault_dir():
    if not VAULT_DIR.exists():
        VAULT_DIR.mkdir(mode=0o700, parents=True)

def _now_ts():
    return datetime.now(timezone.utc).isoformat()

def _rand_base62(nchars):
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.!@#$%^&*"
    # get enough random bytes and map to alphabet
    out = []
    while len(out) < nchars:
        num = int.from_bytes(secrets.token_bytes(6), 'big')
        for _ in range(6):
            if len(out) >= nchars:
                break
            out.append(alphabet[num % len(alphabet)])
            num //= len(alphabet)
    return ''.join(out[:nchars])

def gen_dica_auto():
    return _rand_base62(AUTO_DICA_LEN)

# ---------- KDF & AES ----------
def derive_key(combined: str, salt: bytes, length=DERIVED_KEY_LEN):
    pwd = combined.encode('utf-8')
    if USE_ARGON2:
        raw = hash_secret_raw(secret=pwd, salt=salt,
                              time_cost=ARGON2_TIME,
                              memory_cost=ARGON2_MEM,
                              parallelism=ARGON2_PAR,
                              hash_len=length, type=Type.ID)
        return raw
    else:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt,
                         iterations=PBKDF2_ITERS, backend=default_backend())
        return kdf.derive(pwd)

def aesgcm_encrypt(plaintext: bytes, key: bytes):
    nonce = secrets.token_bytes(NONCE_LEN)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, associated_data=None)  # ciphertext||tag
    return nonce, ct

def aesgcm_decrypt(nonce: bytes, ct: bytes, key: bytes):
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, associated_data=None)

# -------------- GPG wrappers --------------
def _gpg_encrypt_bytes(plain_bytes: bytes, out_path: Path, passphrase: str):
    # write to tmp and call gpg symmetric with passphrase via fd 0
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(plain_bytes)
        tf.flush()
        tmp = tf.name
    cmd = [GPG_BIN, '--batch', '--yes', '--symmetric', '--cipher-algo', 'AES256',
           '--passphrase-fd', '0', '--output', str(out_path), tmp]
    p = subprocess.run(cmd, input=(passphrase + "\n").encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.unlink(tmp)
    if p.returncode != 0:
        raise RuntimeError("gpg encrypt failed: " + p.stderr.decode('utf-8', errors='ignore'))
    return True

def _gpg_decrypt_to_bytes(vault_path: Path, passphrase: str):
    if not vault_path.exists():
        return b''
    cmd = [GPG_BIN, '--batch', '--yes', '--decrypt', '--passphrase-fd', '0', str(vault_path)]
    p = subprocess.run(cmd, input=(passphrase + "\n").encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError("gpg decrypt failed: " + p.stderr.decode('utf-8', errors='ignore'))
    return p.stdout

# -------------- vault IO --------------
def load_vault(passphrase: str):
    ensure_vault_dir()
    if not VAULT_PATH.exists():
        return {}
    raw = _gpg_decrypt_to_bytes(VAULT_PATH, passphrase)
    if not raw:
        return {}
    try:
        return json.loads(raw.decode('utf-8'))
    except Exception as e:
        raise RuntimeError("vault JSON parse failed: " + str(e))

def save_vault(vobj: dict, passphrase: str):
    ensure_vault_dir()
    plain = json.dumps(vobj, ensure_ascii=False, indent=2).encode('utf-8')
    return _gpg_encrypt_bytes(plain, VAULT_PATH, passphrase)

def backup_vault_auto():
    if not VAULT_PATH.exists():
        return
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    bak = VAULT_PATH.parent / f"vault.gpg.bak.{ts}"
    with open(VAULT_PATH, 'rb') as fsrc, open(bak, 'wb') as fdst:
        fdst.write(fsrc.read())
    # prune older backups (keep last BACKUP_KEEP)
    backups = sorted(VAULT_PATH.parent.glob("vault.gpg.bak.*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[BACKUP_KEEP:]:
        try:
            old.unlink()
        except Exception:
            pass

# ---------------- Operations (menu) ----------------
def op_add(vault: dict, passphrase: str):
    print("\n--- Adicionar nova entrada ---")
    label = input("Label (nome identificador): ").strip()
    if not label:
        print("Label vazio; abortando.")
        return
    if label in vault:
        print("Já existe um registro com esse label.")
        return

    dica1_name = input("Dica 1 (nome descritivo): ").strip()
    dica2_name = input("Dica 2 (nome descritivo): ").strip()

    k1 = input("Valor para Dica 1 (pressione Enter para gerar automaticamente): ").strip()
    if not k1:
        k1 = gen_dica_auto()

    k2 = input("Valor para Dica 2 (pressione Enter para gerar automaticamente): ").strip()
    if not k2:
        k2 = gen_dica_auto()

    secret = getpass.getpass("Senha / secret (será oculta): ")
    if not secret:
        print("Senha vazia; abortando.")
        return

    # Encrypt secret with derived key from k1|k2
    combined = k1 + "|" + k2
    salt = secrets.token_bytes(SALT_LEN)
    derived = derive_key(combined, salt)
    nonce, ct = aesgcm_encrypt(secret.encode('utf-8'), derived)

    entry = {
        "meta": {
            "dica1_name": dica1_name or "Dica1",
            "dica2_name": dica2_name or "Dica2",
            "created": _now_ts()
        },
        "data": {
            "salt": binascii.hexlify(salt).decode('ascii'),
            "nonce": binascii.hexlify(nonce).decode('ascii'),
            "cipher_b64": base64.b64encode(ct).decode('ascii')
        }
    }

    # backup and save
    backup_vault_auto()
    vault[label] = entry
    try:
        save_vault(vault, passphrase)
    except Exception as e:
        print("Erro ao salvar vault:", e)
        return

    print("\n✅ ADICIONADO:", label)
    print(f"[{entry['meta']['dica1_name']}]: {k1}")
    print(f"[{entry['meta']['dica2_name']}]: {k2}")
    print("\nAnota esses valores em local seguro.")
    if HAVE_CLIP:
        try:
            pyperclip.copy(k1)
            print("(Valor Dica1 copiado para clipboard)")
        except Exception:
            pass

def op_get(vault: dict, passphrase: str):
    print("\n--- Recuperar entrada ---")
    label = input("Label (nome identificador): ").strip()
    if label not in vault:
        print("Registro não encontrado.")
        return
    entry = vault[label]
    meta = entry.get("meta", {})
    d1_name = meta.get("dica1_name", "Dica1")
    d2_name = meta.get("dica2_name", "Dica2")

    v1 = input(f"Digite [{d1_name}]: ").strip()
    v2 = input(f"Digite [{d2_name}]: ").strip()

    try:
        salt = binascii.unhexlify(entry["data"]["salt"])
        nonce = binascii.unhexlify(entry["data"]["nonce"])
        ct = base64.b64decode(entry["data"]["cipher_b64"])
    except Exception:
        print("Entrada corrompida.")
        return

    combined = v1 + "|" + v2
    derived = derive_key(combined, salt)
    try:
        pt = aesgcm_decrypt(nonce, ct, derived)
    except Exception:
        print("Dicas incorretas ou dados corrompidos (não foi possível decriptar).")
        return

    secret = pt.decode('utf-8')
    print(f"\nLabel: {label}")
    print(f"Senha: {secret}")
    if HAVE_CLIP:
        try:
            pyperclip.copy(secret)
            print("(Senha copiada para clipboard)")
        except Exception:
            pass

def op_list(vault: dict, passphrase: str):
    print("\n--- Labels cadastrados ---")
    if not vault:
        print("(nenhum registro)")
        return
    for k in sorted(vault.keys(), key=lambda s: s.lower()):
        print("-", k)

def op_delete(vault: dict, passphrase: str):
    print("\n--- Excluir entrada ---")
    label = input("Label a excluir: ").strip()
    if not label:
        print("Label vazio.")
        return
    if label not in vault:
        print("Registro não encontrado.")
        return
    confirm = input(f"Confirma remoção de '{label}'? Digite o label completo para confirmar: ")
    if confirm != label:
        print("Confirmação incorreta. Abortando.")
        return
    backup_vault_auto()
    del vault[label]
    try:
        save_vault(vault, passphrase)
    except Exception as e:
        print("Erro ao salvar vault:", e)
        return
    print("Removido com sucesso.")

def op_backup(vault: dict, passphrase: str):
    print("\n--- Backup manual do vault ---")
    ensure_vault_dir()
    if not VAULT_PATH.exists():
        print("Vault não existe. Nada a exportar.")
        return
    dest = VAULT_PATH.parent / f"vault.gpg.manualbak.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    with open(VAULT_PATH, 'rb') as fsrc, open(dest, 'wb') as fdst:
        fdst.write(fsrc.read())
    print("Backup criado:", dest)

# -------------- menu --------------
def menu_loop():
    print("Token Vault Secure - menu interativo")
    passphrase = getpass.getpass("Passphrase do cofre (será solicitada): ")
    try:
        vault = load_vault(passphrase)
    except Exception as e:
        print("Erro ao abrir vault:", e)
        return

    while True:
        print("\nEscolha uma opção:")
        print("1 - Adicionar entrada")
        print("2 - Recuperar entrada")
        print("3 - Excluir entrada")
        print("4 - Listar labels")
        print("5 - Backup manual")
        print("6 - Sair")
        opt = input("Opção: ").strip()
        if opt == "1":
            op_add(vault, passphrase)
        elif opt == "2":
            op_get(vault, passphrase)
        elif opt == "3":
            op_delete(vault, passphrase)
        elif opt == "4":
            op_list(vault, passphrase)
        elif opt == "5":
            op_backup(vault, passphrase)
        elif opt == "6":
            print("Saindo. Até mais.")
            break
        else:
            print("Opção inválida.")

def main():
    try:
        menu_loop()
    except KeyboardInterrupt:
        print("\nInterrompido. Saindo.")

if __name__ == "__main__":
    main()
