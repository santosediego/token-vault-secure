#!/usr/bin/env python3
"""
token_vault.py - Menu interactive vault using GPG (symmetric) + per-entry AES-GCM
Model B adapted: vault.gpg (symmetric) contains JSON mapping label -> encrypted entry.
Each entry encrypted with a key derived from (dica1_value + '|' + dica2_value) using Argon2 (if available) or PBKDF2.

Usage:
  python token_vault.py
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
from datetime import datetime
from pathlib import Path

# crypto libs
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except Exception:
    print("ERRO: instale a biblioteca 'cryptography' (pip install cryptography)")
    sys.exit(1)

# argon2 optional
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

# Config
HOME = Path.home()
VAULT_DIR = HOME / ".vault"
VAULT_PATH = VAULT_DIR / "vault.gpg"
GPG_BIN = "gpg"

# KDF params
SALT_LEN = 16
NONCE_LEN = 12
ARGON2_TIME = 2
ARGON2_MEM = 65536  # KiB (64 MiB)
ARGON2_PAR = 1
PBKDF2_ITERS = 250_000

TOKEN_BYTES = 15  # used for generating display tokens -- estava 6

# ---------------- helpers ----------------
def ensure_vault_dir():
    if not VAULT_DIR.exists():
        VAULT_DIR.mkdir(mode=0o700, parents=True)

def randhex(n):
    return binascii.hexlify(secrets.token_bytes(n)).decode('ascii')

def gen_display_token():
    # base62-like token for display (short)
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    num = int.from_bytes(secrets.token_bytes(6), 'big')
    out = []
    while len(out) < 8:
        out.append(alphabet[num % len(alphabet)])
        num //= len(alphabet)
    return ''.join(out)

def derive_key(combined: str, salt: bytes, length=32):
    pwd = combined.encode('utf-8')
    if USE_ARGON2:
        raw = hash_secret_raw(secret=pwd, salt=salt, time_cost=ARGON2_TIME,
                              memory_cost=ARGON2_MEM, parallelism=ARGON2_PAR,
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
    pt = aes.decrypt(nonce, ct, associated_data=None)
    return pt

# -------------- GPG wrappers --------------
def gpg_encrypt_bytes(plain_bytes: bytes, vault_path: Path, passphrase: str):
    # writes to tmp file then gpg --symmetric --passphrase-fd 0 --output vault_path tmp
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(plain_bytes)
        tf.flush()
        tmp = tf.name
    cmd = [GPG_BIN, '--batch', '--yes', '--symmetric', '--cipher-algo', 'AES256',
           '--passphrase-fd', '0', '--output', str(vault_path), tmp]
    p = subprocess.run(cmd, input=(passphrase + "\n").encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.unlink(tmp)
    if p.returncode != 0:
        raise RuntimeError("gpg encrypt failed: " + p.stderr.decode('utf-8', errors='ignore'))
    return True

def gpg_decrypt_to_bytes(vault_path: Path, passphrase: str):
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
    try:
        raw = gpg_decrypt_to_bytes(VAULT_PATH, passphrase)
    except Exception as e:
        raise
    if not raw:
        return {}
    try:
        return json.loads(raw.decode('utf-8'))
    except Exception as e:
        raise RuntimeError("vault JSON parse failed: " + str(e))

def save_vault(vobj: dict, passphrase: str):
    ensure_vault_dir()
    plain = json.dumps(vobj, ensure_ascii=False, indent=2).encode('utf-8')
    return gpg_encrypt_bytes(plain, VAULT_PATH, passphrase)

def backup_vault():
    if VAULT_PATH.exists():
        bak = VAULT_PATH.parent / ("vault.gpg.bak." + datetime.utcnow().strftime("%Y%m%d%H%M%S"))
        with open(VAULT_PATH, 'rb') as fsrc, open(bak, 'wb') as fdst:
            fdst.write(fsrc.read())
        print("[backup] created:", bak)

# -------------- operations --------------
def op_add(vault, passphrase):
    print("\n--- Adicionar nova entrada ---")
    label = input("Label (nome identificador): ").strip()
    if not label:
        print("Label vazio; abortando.")
        return
    if label in vault:
        print("Já existe um registro com esse label.")
        return

    dica1_name = input("Dica 1 - nome descritivo: ").strip()
    dica2_name = input("Dica 2 - nome descritivo: ").strip()

    # first key (dica1 value)
    k1 = input("Valor para Dica 1 (pressione Enter para gerar automaticamente): ").strip()
    if not k1:
        k1 = gen_display_token()

    # second key (dica2 value)
    k2 = input("Valor para Dica 2 (pressione Enter para gerar automaticamente): ").strip()
    if not k2:
        k2 = gen_display_token()

    secret = getpass.getpass("Senha / secret (será oculta): ")
    if not secret:
        print("Senha vazia; abortando.")
        return

    # encrypt secret using key derived from k1|k2
    combined = k1 + '|' + k2
    salt = secrets.token_bytes(SALT_LEN)
    derived = derive_key(combined, salt)
    nonce, ct = aesgcm_encrypt(secret.encode('utf-8'), derived)

    entry = {
        "meta": {
            "dica1_name": dica1_name,
            "dica2_name": dica2_name,
            "created": datetime.utcnow().isoformat() + "Z"
        },
        "data": {
            "salt": binascii.hexlify(salt).decode('ascii'),
            "nonce": binascii.hexlify(nonce).decode('ascii'),
            "cipher_b64": base64.b64encode(ct).decode('ascii')
        }
    }

    backup_vault()
    vault[label] = entry
    try:
        save_vault(vault, passphrase)
    except Exception as e:
        print("Erro ao salvar vault:", e)
        return

    # Show only the hints (values) for user to record — do not reveal secret
    print("\n✅ ADICIONADO:", label)
    if dica1_name:
        print(f"[{dica1_name}]: {k1}")
    else:
        print(f"[Dica1]: {k1}")
    if dica2_name:
        print(f"[{dica2_name}]: {k2}")
    else:
        print(f"[Dica2]: {k2}")
    print("\nAnota esses pares nos locais que escolher (em local seguro).")
    if HAVE_CLIP:
        try:
            pyperclip.copy(k1)
            print("(Dica1 copiada para clipboard)")
        except Exception:
            pass

def op_get(vault, passphrase):
    print("\n--- Recuperar entrada ---")
    label = input("Label (nome identificador): ").strip()
    if label not in vault:
        print("Registro não encontrado.")
        return
    entry = vault[label]
    meta = entry.get("meta", {})
    d1_name = meta.get("dica1_name", "Dica1")
    d2_name = meta.get("dica2_name", "Dica2")

    # prompt for the values (showing hint name)
    v1 = input(f"Digite [{d1_name}]: ").strip()
    v2 = input(f"Digite [{d2_name}]: ").strip()

    # derive and try decrypt
    try:
        salt = binascii.unhexlify(entry["data"]["salt"])
        nonce = binascii.unhexlify(entry["data"]["nonce"])
        ct = base64.b64decode(entry["data"]["cipher_b64"])
    except Exception:
        print("Entrada corrompida.")
        return

    combined = v1 + '|' + v2
    derived = derive_key(combined, salt)
    try:
        pt = aesgcm_decrypt(nonce, ct, derived)
    except Exception:
        print("Dicas incorretas ou dados corrompidos (não foi possível decriptar).")
        return

    secret = pt.decode('utf-8')
    print(f"\n🔐 Label: {label}")
    print(f"Senha: {secret}")
    if HAVE_CLIP:
        try:
            pyperclip.copy(secret)
            print("(Senha copiada para clipboard)")
        except Exception:
            pass

def op_list(vault, passphrase):
    print("\n--- Labels cadastrados ---")
    if not vault:
        print("(nenhum registro)")
        return
    for k in sorted(vault.keys(), key=lambda s: s.lower()):
        print("-", k)

def op_delete(vault, passphrase):
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
    backup_vault()
    del vault[label]
    try:
        save_vault(vault, passphrase)
    except Exception as e:
        print("Erro ao salvar vault:", e)
        return
    print("Removido com sucesso.")

# -------------- menu --------------
def menu_loop():
    print("🔐 Token Vault - menu interativo (modelo B com GPG)")
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
        print("5 - Sair")
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
