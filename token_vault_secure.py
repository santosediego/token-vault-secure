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
import re
import gc
import threading
import time
import random
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

CLIPBOARD_TIMEOUT = 30  # segundos antes de limpar

# ---------------- helpers ----------------
# remove sequências ANSI / escape (ex.: ^[[F) e qualquer caractere não imprimível
_ANSI_ESC_RE = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]|\x1B\[[0-9;]*[A-Za-z]')

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

def sanitize_text(s: str, maxlen: int = None) -> str:
    """
    Remove sequências de escape ANSI e caracteres não imprimíveis.
    Retorna string ASCII imprimível (0x20..0x7E). Trim opcional por maxlen.
    """
    if s is None:
        return ''
    # remove escapes ANSI (inclui \x1b[... sequences)
    s = _ANSI_ESC_RE.sub('', s)
    # keep only printable ASCII (space (32) .. til (~ 126))
    s = ''.join(ch for ch in s if 32 <= ord(ch) <= 126)
    # collapse multiple spaces to single, trim
    s = ' '.join(s.split())
    if maxlen is not None and len(s) > maxlen:
        s = s[:maxlen]
    return s

def is_valid_label(label: str) -> bool:
    """Permite apenas caracteres seguros no label"""
    return bool(re.match(r'^[\w\s\-@.]+$', label))

def copy_with_timeout(text: str, timeout=CLIPBOARD_TIMEOUT):
    """Copia texto e limpa o clipboard após timeout"""
    if not HAVE_CLIP:
        return
    try:
        pyperclip.copy(text)
        print(f"(Copiado para clipboard — limparei em {timeout}s)")
        def clear_clip():
            time.sleep(timeout)
            try:
                if pyperclip.paste() == text:
                    pyperclip.copy('')
                    print("(Clipboard limpo automaticamente)")
            except Exception:
                pass
        threading.Thread(target=clear_clip, daemon=True).start()
    except Exception:
        pass

# ---------- KDF & AES ----------
def derive_key(combined: str, salt: bytes, length=DERIVED_KEY_LEN):
    pwd = combined.encode('utf-8')
    if USE_ARGON2:
        return hash_secret_raw(
            secret=pwd, salt=salt,
            time_cost=ARGON2_TIME,
            memory_cost=ARGON2_MEM,
            parallelism=ARGON2_PAR,
            hash_len=length, type=Type.ID
        )
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
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(plain_bytes)
        tf.flush()
        tmp = tf.name
    cmd = [
        GPG_BIN, '--batch', '--yes', '--symmetric', '--cipher-algo', 'AES256',
        '--passphrase-fd', '0', '--output', str(out_path), tmp
    ]
    p = subprocess.run(cmd, input=(passphrase + "\n").encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with open(tmp, 'wb') as f:
            f.write(b'\x00' * len(plain_bytes))
        os.unlink(tmp)
    except Exception:
        pass
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors='ignore').strip())
    return True

def _gpg_decrypt_to_bytes(vault_path: Path, passphrase: str):
    if not vault_path.exists():
        return b''
    cmd = [GPG_BIN, '--batch', '--yes', '--decrypt',
           '--passphrase-fd', '0', str(vault_path)]
    p = subprocess.run(cmd, input=(passphrase + "\n").encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors='ignore').strip())
    return p.stdout

# -------------- vault IO --------------
def load_vault(passphrase: str):
    ensure_vault_dir()
    if not VAULT_PATH.exists():
        return {}
    raw = _gpg_decrypt_to_bytes(VAULT_PATH, passphrase)
    return json.loads(raw.decode('utf-8')) if raw else {}

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

def op_change_master_password(vault: dict, old_passphrase: str):
    print("\n--- Trocar senha mestra ---")
    confirm = getpass.getpass("Confirme senha mestra atual: ")
    if confirm != old_passphrase:
        print("Senha incorreta. Abortando.")
        return old_passphrase

    new1 = getpass.getpass("Nova senha mestra: ")
    new2 = getpass.getpass("Confirme nova senha: ")
    if not new1 or new1 != new2:
        print("Senhas não conferem ou vazias.")
        return old_passphrase

    # backup antes de trocar
    backup_vault_auto()
    try:
        save_vault(vault, new1)
        type_effect("Senha mestra atualizada com sucesso!", 0.02)
        return new1
    except Exception as e:
        print("Erro ao salvar com nova senha:", e)
        return old_passphrase

# ---------------- Operations (menu) ----------------
def op_add(vault, passphrase):
    print("\n--- Adicionar nova entrada ---")
    label = sanitize_text(input("Label (nome identificador): "), maxlen=120)
    if not label or not is_valid_label(label):
        print("Label inválido.")
        return
    if label in vault:
        print("Já existe um registro com esse label.")
        return
    dica1_name = sanitize_text(input("Dica 1 (descrição): "), maxlen=120)
    dica2_name = sanitize_text(input("Dica 2 (descrição): "), maxlen=120)
    k1 = sanitize_text(input("Valor Dica 1 (Enter p/ gerar): ")) or gen_dica_auto()
    k2 = sanitize_text(input("Valor Dica 2 (Enter p/ gerar): ")) or gen_dica_auto()
    secret = getpass.getpass("Senha / secret: ")
    if not secret:
        print("Senha vazia; abortando.")
        return

    # Encrypt secret with derived key from k1|k2
    combined = k1 + "|" + k2
    salt = secrets.token_bytes(SALT_LEN)
    derived = derive_key(combined, salt)
    nonce, ct = aesgcm_encrypt(secret.encode(), derived)
    entry = {
        "meta": {"dica1_name": dica1_name or "Dica1",
                 "dica2_name": dica2_name or "Dica2",
                 "created": _now_ts()},
        "data": {"salt": binascii.hexlify(salt).decode(),
                 "nonce": binascii.hexlify(nonce).decode(),
                 "cipher_b64": base64.b64encode(ct).decode()}
    }

    # backup and save
    backup_vault_auto()
    vault[label] = entry
    save_vault(vault, passphrase)
    print("\nADICIONADO:", label)
    print(f"[{entry['meta']['dica1_name']}]: {k1}")
    print(f"[{entry['meta']['dica2_name']}]: {k2}")
    copy_with_timeout(k1)
    gc.collect()

def op_get(vault, passphrase):
    print("\n--- Recuperar entrada ---")
    label = sanitize_text(input("Label: "), maxlen=120)
    if label not in vault:
        print("Registro não encontrado.")
        return
    entry = vault[label]
    meta = entry.get("meta", {})
    d1_name = meta.get("dica1_name", "Dica1")
    d2_name = meta.get("dica2_name", "Dica2")
    v1 = sanitize_text(input(f"Digite [{d1_name}]: "))
    v2 = sanitize_text(input(f"Digite [{d2_name}]: "))
    salt = binascii.unhexlify(entry["data"]["salt"])
    nonce = binascii.unhexlify(entry["data"]["nonce"])
    ct = base64.b64decode(entry["data"]["cipher_b64"])
    combined = v1 + "|" + v2
    derived = derive_key(combined, salt)
    try:
        secret = aesgcm_decrypt(nonce, ct, derived).decode()
        print(f"\nLabel: {label}")
        print(f"Senha: {secret}")
        copy_with_timeout(secret)
    except Exception:
        print("Dicas incorretas ou dados corrompidos.")
    gc.collect()

def op_list(vault: dict, passphrase: str):
    print("\n--- Labels cadastrados ---")
    if not vault:
        print("(nenhum registro)")
        return
    for k in sorted(vault.keys(), key=lambda s: s.lower()):
        print("-", k)

def op_delete(vault: dict, passphrase: str):
    print("\n--- Excluir entrada ---")
    label = sanitize_text(input("Label a excluir: "), maxlen=120)
    if not label:
        print("Label vazio.")
        return
    if label not in vault:
        print("Registro não encontrado.")
        return
    confirm = sanitize_text(input(f"Confirma remoção de '{label}'? Digite o label completo para confirmar: "), maxlen=120)
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

def op_edit(vault: dict, passphrase: str):
    print("\n--- Editar entrada ---")
    label = sanitize_text(input("Label da entrada: "), maxlen=120)
    if not label:
        print("Label vazio.")
        return
    if label not in vault:
        print("Registro não encontrado.")
        return

    entry = vault[label]
    meta = entry.get("meta", {})
    data = entry.get("data", {})
    d1_name = meta.get("dica1_name", "Dica1")
    d2_name = meta.get("dica2_name", "Dica2")

    # Pedir as dicas atuais para decriptar a senha
    v1 = sanitize_text(input(f"Digite [{d1_name}] atual: "))
    v2 = sanitize_text(input(f"Digite [{d2_name}] atual: "))
    try:
        salt = binascii.unhexlify(data["salt"])
        nonce = binascii.unhexlify(data["nonce"])
        ct = base64.b64decode(data["cipher_b64"])
        derived = derive_key(v1 + "|" + v2, salt)
        secret_old = aesgcm_decrypt(nonce, ct, derived).decode('utf-8')
    except Exception:
        print("Dicas incorretas ou dados corrompidos. Abortando.")
        return

    print("\nValores atuais:")
    print(f"Label: {label}")
    print(f"{d1_name}: {v1}")
    print(f"{d2_name}: {v2}")
    print(f"Senha atual: {secret_old}")
    print("Deixe em branco para manter o valor atual.\n")

    # Coletar novos valores (se informados)
    new_d1_name = sanitize_text(input(f"Novo nome para [{d1_name}]: "), maxlen=120) or d1_name
    new_d2_name = sanitize_text(input(f"Novo nome para [{d2_name}]: "), maxlen=120) or d2_name
    new_v1 = sanitize_text(input(f"Novo valor para [{new_d1_name}]: ")) or v1
    new_v2 = sanitize_text(input(f"Novo valor para [{new_d2_name}]: ")) or v2
    new_secret = getpass.getpass("Nova senha (Enter para manter): ") or secret_old

    # Criptografa novamente com os novos valores
    combined = new_v1 + "|" + new_v2
    salt = secrets.token_bytes(SALT_LEN)
    derived = derive_key(combined, salt)
    nonce, ct = aesgcm_encrypt(new_secret.encode('utf-8'), derived)

    entry = {
        "meta": {
            "dica1_name": new_d1_name,
            "dica2_name": new_d2_name,
            "created": meta.get("created", _now_ts()),
            "updated": _now_ts()
        },
        "data": {
            "salt": binascii.hexlify(salt).decode('ascii'),
            "nonce": binascii.hexlify(nonce).decode('ascii'),
            "cipher_b64": base64.b64encode(ct).decode('ascii')
        }
    }

    # backup + salvar
    backup_vault_auto()
    vault[label] = entry
    try:
        save_vault(vault, passphrase)
    except Exception as e:
        print("Erro ao salvar alterações:", e)
        return

    print("\nEntrada atualizada com sucesso.")
    print(f"[{entry['meta']['dica1_name']}]: {new_v1}")
    print(f"[{entry['meta']['dica2_name']}]: {new_v2}")
    print("Anote novamente esses valores.")
    del secret_old, derived, combined
    gc.collect()

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

def _parse_bak_ts(name: str) -> str:
    """
    Recebe um nome como 'vault.gpg.bak.20251110165144' e retorna
    '2025-11-10 16:51:44' para exibição. Se não conseguir, retorna o nome.
    """
    try:
        ts = name.rsplit('.', 1)[-1]
        dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return name

def op_restore(vault: dict, passphrase: str):
    """
    Lista backups disponíveis e permite restaurar um escolhendo pelo número.
    Retorna o novo objeto vault (recarregado) ou o vault original se cancelar/erro.
    """
    print("\n--- Restaurar backup ---")
    ensure_vault_dir()

    # coletar backups (manuais e automáticos)
    candidates = []
    for p in sorted(VAULT_DIR.glob("vault.gpg.bak.*"), key=lambda p: p.stat().st_mtime, reverse=True):
        candidates.append(p)
    for p in sorted(VAULT_DIR.glob("vault.gpg.manualbak.*"), key=lambda p: p.stat().st_mtime, reverse=True):
        candidates.append(p)

    if not candidates:
        print("Nenhum backup encontrado em:", VAULT_DIR)
        return vault

    # mostrar lista com índices
    print("Backups encontrados:")
    for i, p in enumerate(candidates, start=1):
        pretty = _parse_bak_ts(p.name)
        print(f"{i:2d}. {p.name}  ({pretty})")

    print("\nDigite o número do backup para restaurar, ou Enter para cancelar.")
    sel = input("Número: ").strip()
    if not sel:
        print("Restauração cancelada.")
        return vault

    try:
        idx = int(sel) - 1
        if idx < 0 or idx >= len(candidates):
            print("Número inválido. Abortando.")
            return vault
    except ValueError:
        print("Entrada inválida. Abortando.")
        return vault

    chosen = candidates[idx]
    pretty_chosen = _parse_bak_ts(chosen.name)
    confirm = sanitize_text(input(f"Confirma restaurar '{chosen.name}' ({pretty_chosen}) ? (digite YES para confirmar): ")).strip()
    if confirm != "YES":
        print("Restauração não confirmada. Abortando.")
        return vault

    # salvar cópia do arquivo atual antes de substituir
    if VAULT_PATH.exists():
        tmp_save = VAULT_PATH.parent / f"vault.gpg.pre_restore.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        try:
            with open(VAULT_PATH, 'rb') as fsrc, open(tmp_save, 'wb') as fdst:
                fdst.write(fsrc.read())
            print(f"Cópia do vault atual salva em: {tmp_save.name}")
        except Exception as e:
            print("Falha ao salvar cópia do vault atual:", e)
            return vault

    # copiar o escolhido para vault.gpg
    try:
        with open(chosen, 'rb') as fsrc, open(VAULT_PATH, 'wb') as fdst:
            fdst.write(fsrc.read())
    except Exception as e:
        print("Erro ao restaurar arquivo:", e)
        return vault

    # tentar recarregar cofre com a passphrase atual
    try:
        new_vault = load_vault(passphrase)
        print("Backup restaurado com sucesso e cofre recarregado.")
        return new_vault
    except Exception as e:
        print("Backup restaurado, mas falha ao recarregar o cofre com a passphrase atual:", e)
        print("Se a passphrase for diferente para esse backup, utilize a opção de carregar manualmente.")
        return vault

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    input("\nPressione Enter para continuar...")

def header():
    print("Token Vault Secure - menu interativo")

def type_effect(text, delay=0.02, newline=True):
    """Imprime texto com efeito de digitação."""
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
        print()

def print_banner(title="Token Vault Secure", version="v1.0"):
    frases = [
        "A segurança começa na simplicidade.",
        "Sem distrações, só propósito.",
        "Tudo sob controle — de forma discreta.",
        "Cada bit no seu devido lugar.",
        "Feito por quem gosta de ver as engrenagens girarem."
    ]
    use_color = False
    t = f"{title} {version}"
    width = 60
    pad = (width - len(t)) // 2
    top = " " * pad + t + " " * (width - len(t) - pad)
    esc = "\x1b[1;30m" if use_color else ""
    reset = "\x1b[0m" if use_color else ""

    print()
    print(esc + "+" + "-" * (width) + "+" + reset)
    print(esc + "|" + top + "|" + reset)
    print(esc + "+" + "-" * (width) + "+" + reset)
    print(esc + "  " + random.choice(frases) + reset)
    print()

# -------------- menu --------------
def menu_loop():
    header()
    passphrase = getpass.getpass("Passphrase do cofre (será solicitada): ")
    try:
        vault = load_vault(passphrase)
    except Exception as e:
        print("Erro ao abrir vault:", e)
        return

    while True:
        clear_screen()
        print_banner("Token Vault Secure", "v0.4.1")
        print("\nEscolha uma opção:")
        print("1 - Adicionar entrada")
        print("2 - Recuperar entrada")
        print("3 - Editar entrada")
        print("4 - Excluir entrada")
        print("5 - Listar labels")
        print("6 - Backup manual")
        print("7 - Trocar senha mestra")
        print("8 - Restaurar backup")
        print("99 - Sair")
        opt = input("Opção: ").strip()
        if opt == "1":
            clear_screen()
            op_add(vault, passphrase)
            pause()
        elif opt == "2":
            clear_screen()
            op_get(vault, passphrase)
            pause()
        elif opt == "3":
            clear_screen()
            op_edit(vault, passphrase)
            pause()
        elif opt == "4":
            op_delete(vault, passphrase)
            pause()
        elif opt == "5":
            clear_screen()
            op_list(vault, passphrase)
            pause()
        elif opt == "6":
            op_backup(vault, passphrase)
            pause()
        elif opt == "7":
            passphrase = op_change_master_password(vault, passphrase)
            pause()
        elif opt == "8":
            clear_screen()
            # op_restore retorna o vault recarregado (ou o original)
            vault = op_restore(vault, passphrase)
            pause()
        elif opt == "99":
            type_effect("Saindo... até a próxima!", 0.02)
            break
        else:
            print("Opção inválida.")
            pause()

def main():
    try:
        menu_loop()
    except KeyboardInterrupt:
        print("\nInterrompido. Saindo.")

if __name__ == "__main__":
    main()
