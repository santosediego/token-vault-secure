#!/usr/bin/env python3
"""
token_vault_b.py  -- Modelo B: vault.gpg + secrets cifrados por-key (Argon2/PBKDF2 + AES-GCM)

Funcionalidades: add, get, list, delete, backup

Dependências:
 - gpg (CLI)
 - python packages (recommended): cryptography, argon2_cffi, pyperclip

Instalação:
 pip install cryptography argon2-cffi pyperclip
"""

import argparse
import json
import os
import sys
import tempfile
import subprocess
import base64
import secrets
import binascii
from datetime import datetime
import getpass

# crypto libs
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except Exception as e:
    print("ERRO: instale 'cryptography'. pip install cryptography", file=sys.stderr)
    raise

# argon2 optional
USE_ARGON2 = False
try:
    from argon2.low_level import hash_secret_raw, Type
    USE_ARGON2 = True
except Exception:
    USE_ARGON2 = False

# clipboard optional
try:
    import pyperclip
    HAVE_CLIP = True
except Exception:
    HAVE_CLIP = False

# -------- parameters (safe defaults) ----------
GPG_BIN = "gpg"
TOKEN_LEN = 6  # comprimento token curto
SALT_LEN = 16  # bytes
NONCE_LEN = 12 # bytes for AESGCM
PBKDF2_ITERS = 250_000
ARGON2_TIME = 2
ARGON2_MEM = 65536  # KiB => 64 MiB
ARGON2_PAR = 1
# ---------------------------------------------

def randhex(nbytes):
    return binascii.hexlify(secrets.token_bytes(nbytes)).decode('ascii')

def derive_key_from_passphrase(passphrase: str, salt: bytes, length=32):
    """
    Deriva chave de cifragem a partir da 'key' da conta.
    Usa Argon2id se disponível, senão PBKDF2-HMAC-SHA256.
    """
    pwd = passphrase.encode('utf-8')
    if USE_ARGON2:
        # Argon2id: returns raw bytes
        raw = hash_secret_raw(secret=pwd,
                              salt=salt,
                              time_cost=ARGON2_TIME,
                              memory_cost=ARGON2_MEM,
                              parallelism=ARGON2_PAR,
                              hash_len=length,
                              type=Type.ID)
        return raw
    else:
        # fallback PBKDF2
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt,
                         iterations=PBKDF2_ITERS, backend=default_backend())
        return kdf.derive(pwd)

def aesgcm_encrypt(plaintext: bytes, key: bytes):
    nonce = secrets.token_bytes(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct  # ct includes tag

def aesgcm_decrypt(nonce: bytes, ct: bytes, key: bytes):
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, associated_data=None)
    return pt

def gpg_encrypt_bytes(plain_bytes: bytes, vault_path: str, passphrase: str):
    # write to tmp file and call gpg symmetric, reading passphrase from stdin (--passphrase-fd 0)
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(plain_bytes)
        tf.flush()
        tmpname = tf.name
    cmd = [GPG_BIN, '--batch', '--yes', '--symmetric', '--cipher-algo', 'AES256',
           '--passphrase-fd', '0', '--output', vault_path, tmpname]
    p = subprocess.run(cmd, input=(passphrase + "\n").encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.unlink(tmpname)
    if p.returncode != 0:
        raise RuntimeError("gpg encrypt failed: " + p.stderr.decode('utf-8', errors='ignore'))
    return True

def gpg_decrypt_to_bytes(vault_path: str, passphrase: str):
    # decrypt to bytes and return them
    if not os.path.exists(vault_path):
        return b''
    cmd = [GPG_BIN, '--batch', '--yes', '--decrypt', '--passphrase-fd', '0', vault_path]
    p = subprocess.run(cmd, input=(passphrase + "\n").encode('utf-8'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError("gpg decrypt failed: " + p.stderr.decode('utf-8', errors='ignore'))
    return p.stdout

def load_vault(vault_path: str, gpg_passphrase: str):
    try:
        raw = gpg_decrypt_to_bytes(vault_path, gpg_passphrase)
    except Exception as e:
        raise
    if not raw:
        return {}
    try:
        return json.loads(raw.decode('utf-8'))
    except Exception as e:
        raise RuntimeError("vault JSON parse failed: " + str(e))

def save_vault(vault_obj: dict, vault_path: str, gpg_passphrase: str):
    plain = json.dumps(vault_obj, ensure_ascii=False, indent=2).encode('utf-8')
    return gpg_encrypt_bytes(plain, vault_path, gpg_passphrase)

def gen_token(secret_seed: str, length=TOKEN_LEN):
    # derive token pseudo-randomly
    hm = secrets.token_bytes(8)  # random
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    num = int.from_bytes(hm, 'big')
    out = []
    while len(out) < length:
        out.append(alphabet[num % len(alphabet)])
        num //= len(alphabet)
    return ''.join(out)

def ensure_vault_backup(vault_path):
    if os.path.exists(vault_path):
        bak = vault_path + ".bak." + datetime.utcnow().strftime("%Y%m%d%H%M%S")
        with open(vault_path, 'rb') as fsrc, open(bak, 'wb') as fdst:
            fdst.write(fsrc.read())
        print(f"[backup] vault backup created: {bak}")

def add_entry(args):
    vault_path = args.vault
    label = args.label
    # get passphrase GPG interactively
    gpg_pass = getpass.getpass("Passphrase do vault (GPG) [será solicitada]: ")
    # load existing vault (or empty)
    try:
        vault = load_vault(vault_path, gpg_pass)
    except Exception as e:
        print("Erro ao abrir vault:", e, file=sys.stderr)
        sys.exit(2)
    # obtain key (either keyfile or typed)
    key_input = None
    if args.keyfile:
        if not os.path.exists(args.keyfile):
            print("keyfile não encontrado:", args.keyfile, file=sys.stderr); sys.exit(3)
        with open(args.keyfile, 'rb') as kf:
            key_input = kf.read().hex()  # use as hex string
    else:
        key_input = getpass.getpass("Chave da conta (digite uma palavra/frasememória ou pressione Enter para usar keyfile): ")
        if not key_input:
            print("Nenhuma key informada; abortando.", file=sys.stderr); sys.exit(4)
    secret = None
    if args.secret:
        secret = args.secret
    else:
        secret = getpass.getpass("Senha / secret (será oculta): ")
    if not secret:
        print("Nenhum secret informado; abortando.", file=sys.stderr); sys.exit(5)

    # generate token avoiding collisions
    tries = 0
    token = None
    while tries < 50:
        candidate = gen_token(secret + key_input + str(tries))
        if candidate not in vault:
            token = candidate
            break
        tries += 1
    if token is None:
        print("Falha ao gerar token sem colisão; aumenta TOKEN_LEN.", file=sys.stderr); sys.exit(6)

    # derive per-entry salt, derive key, encrypt secret
    salt = secrets.token_bytes(SALT_LEN)
    derived = derive_key_from_passphrase(key_input, salt)
    nonce, ct = aesgcm_encrypt(secret.encode('utf-8'), derived)

    entry = {
        "label": label or "",
        "salt": binascii.hexlify(salt).decode('ascii'),
        "nonce": binascii.hexlify(nonce).decode('ascii'),
        "cipher_b64": base64.b64encode(ct).decode('ascii'),
        "created": datetime.utcnow().isoformat() + "Z"
    }

    # backup existing vault then save
    ensure_vault_backup(vault_path)
    vault[token] = entry
    try:
        save_vault(vault, vault_path, gpg_pass)
    except Exception as e:
        print("Erro ao salvar vault:", e, file=sys.stderr); sys.exit(7)

    print("ADICIONADO:", token)
    print("Anota A: {} -> {}".format(label, token))
    print("Anota B: {} -> (sua key)".format(label))
    if HAVE_CLIP:
        try:
            pyperclip.copy(token)
            print("(token copiado para clipboard)")
        except Exception:
            pass

def get_entry(args):
    vault_path = args.vault
    token = args.token
    if not token:
        print("get precisa de --token", file=sys.stderr); sys.exit(1)
    gpg_pass = getpass.getpass("Passphrase do vault (GPG): ")
    try:
        vault = load_vault(vault_path, gpg_pass)
    except Exception as e:
        print("Erro ao abrir vault:", e, file=sys.stderr)
        sys.exit(2)
    if token not in vault:
        print("Token não encontrado.", file=sys.stderr); sys.exit(3)
    entry = vault[token]
    # get key (from keyfile or typed)
    if args.keyfile:
        if not os.path.exists(args.keyfile):
            print("keyfile não encontrado:", args.keyfile, file=sys.stderr); sys.exit(4)
        with open(args.keyfile, 'rb') as kf:
            key_input = kf.read().hex()
    else:
        key_input = getpass.getpass("Chave da conta (digite a key): ")
        if not key_input:
            print("Nenhuma key informada; abortando.", file=sys.stderr); sys.exit(5)

    try:
        salt = binascii.unhexlify(entry['salt'])
        nonce = binascii.unhexlify(entry['nonce'])
        ct = base64.b64decode(entry['cipher_b64'])
    except Exception as e:
        print("Entrada corrompida:", e, file=sys.stderr); sys.exit(6)

    derived = derive_key_from_passphrase(key_input, salt)
    try:
        pt = aesgcm_decrypt(nonce, ct, derived)
    except Exception:
        print("Falha ao decriptar: chave inválida ou dados corrompidos.", file=sys.stderr)
        sys.exit(7)
    secret = pt.decode('utf-8')
    print("LABEL:", entry.get('label', '-'))
    print("SECRET:", secret)
    if HAVE_CLIP:
        try:
            pyperclip.copy(secret)
            print("(secret copiado para clipboard por 30s)")
        except Exception:
            pass

def list_entries(args):
    vault_path = args.vault
    gpg_pass = getpass.getpass("Passphrase do vault (GPG) para listar: ")
    try:
        vault = load_vault(vault_path, gpg_pass)
    except Exception as e:
        print("Erro ao abrir vault:", e, file=sys.stderr)
        sys.exit(2)
    for t, v in vault.items():
        print(t, "→", v.get('label','-'))

def delete_entry(args):
    vault_path = args.vault
    token = args.token
    if not token:
        print("delete precisa de --token", file=sys.stderr); sys.exit(1)
    gpg_pass = getpass.getpass("Passphrase do vault (GPG): ")
    try:
        vault = load_vault(vault_path, gpg_pass)
    except Exception as e:
        print("Erro ao abrir vault:", e, file=sys.stderr); sys.exit(2)
    if token not in vault:
        print("Token não existe.", file=sys.stderr); sys.exit(3)
    confirm = input(f"Confirma remoção de {token} ({vault[token].get('label','-')})? digite CONFIRM {token}: ")
    if confirm.strip() != f"CONFIRM {token}":
        print("Confirmação inválida; abortando.")
        sys.exit(4)
    ensure_vault_backup(vault_path)
    del vault[token]
    try:
        save_vault(vault, vault_path, gpg_pass)
    except Exception as e:
        print("Erro ao salvar vault:", e, file=sys.stderr); sys.exit(5)
    print("Removido:", token)

def backup_vault(args):
    vault_path = args.vault
    dest = args.dest or (vault_path + ".bak." + datetime.utcnow().strftime("%Y%m%d%H%M%S"))
    if not os.path.exists(vault_path):
        print("Vault não existe.", file=sys.stderr); sys.exit(1)
    # just copy file
    with open(vault_path, 'rb') as fsrc, open(dest, 'wb') as fdst:
        fdst.write(fsrc.read())
    print("Backup criado:", dest)

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument('--vault', default='./vault.gpg', help='caminho para vault.gpg (default ./vault.gpg)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    a = sub.add_parser('add')
    a.add_argument('--label', required=True)
    a.add_argument('--keyfile', help='usar keyfile em vez de digitar key')
    a.add_argument('--secret', help='opcional: secret na linha de comando (não recomendado)')

    g = sub.add_parser('get')
    g.add_argument('--token', required=True)
    g.add_argument('--keyfile', help='usar keyfile em vez de digitar key')

    l = sub.add_parser('list')

    d = sub.add_parser('delete')
    d.add_argument('--token', required=True)

    b = sub.add_parser('backup')
    b.add_argument('--dest', help='destino do backup')

    return ap.parse_args()

def main():
    args = parse_args()
    try:
        if args.cmd == 'add':
            add_entry(args)
        elif args.cmd == 'get':
            get_entry(args)
        elif args.cmd == 'list':
            list_entries(args)
        elif args.cmd == 'delete':
            delete_entry(args)
        elif args.cmd == 'backup':
            backup_vault(args)
    except RuntimeError as e:
        print("Erro runtime:", e, file=sys.stderr)
        sys.exit(2)

if __name__ == '__main__':
    main()
