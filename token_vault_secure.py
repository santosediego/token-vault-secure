#!/usr/bin/env python3

from __future__ import annotations
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
import argparse
import shutil
import platform
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple, List

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

# ---------------- CONFIG (centralizado) ----------------
HOME = Path.home()
VAULT_DIR = Path(os.getenv("VAULT_DIR", HOME / ".vault"))
VAULT_PATH = Path(os.getenv("VAULT_PATH", VAULT_DIR / "vault.gpg"))
GPG_BIN = os.getenv("GPG_BIN", "gpg")

SALT_LEN = int(os.getenv("VAULT_SALT_LEN", "16"))
NONCE_LEN = int(os.getenv("VAULT_NONCE_LEN", "12"))
DERIVED_KEY_LEN = int(os.getenv("VAULT_DERIVED_LEN", "32"))
ARGON2_TIME = int(os.getenv("VAULT_ARGON2_TIME", "2"))
ARGON2_MEM = int(os.getenv("VAULT_ARGON2_MEM", "65536"))  # KiB
ARGON2_PAR = int(os.getenv("VAULT_ARGON2_PAR", "1"))
PBKDF2_ITERS = int(os.getenv("VAULT_PBKDF2_ITERS", "250000"))

BACKUP_KEEP = int(os.getenv("VAULT_BACKUP_KEEP", "5"))

AUTO_DICA_LEN = int(os.getenv("VAULT_AUTO_DICA_LEN", "24"))
CLIPBOARD_TIMEOUT = int(os.getenv("VAULT_CLIP_TIMEOUT", "30"))

# ---------------- helpers ----------------
_ANSI_ESC_RE = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]|\x1B\[[0-9;]*[A-Za-z]')

def ensure_vault_dir() -> None:
    if not VAULT_DIR.exists():
        VAULT_DIR.mkdir(mode=0o700, parents=True)
    else:
        # garante permissões minimamente seguras
        try:
            VAULT_DIR.chmod(0o700)
        except Exception:
            pass

def _now_ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def _rand_base62(nchars: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.!@#$%^&*"
    out = []
    while len(out) < nchars:
        num = int.from_bytes(secrets.token_bytes(6), 'big')
        for _ in range(6):
            if len(out) >= nchars:
                break
            out.append(alphabet[num % len(alphabet)])
            num //= len(alphabet)
    return ''.join(out[:nchars])

def gen_dica_auto() -> str:
    return _rand_base62(AUTO_DICA_LEN)

def sanitize_text(s: Optional[str], maxlen: Optional[int] = None) -> str:
    if s is None:
        return ''
    s = _ANSI_ESC_RE.sub('', s)
    s = ''.join(ch for ch in s if 32 <= ord(ch) <= 126)
    s = ' '.join(s.split())
    if maxlen is not None and len(s) > maxlen:
        s = s[:maxlen]
    return s

def maybe_b64decode(value: str) -> str:
    """Tenta decodificar a string de Base64; se falhar, retorna o original."""
    if not value:
        return ""
    try:
        decoded = base64.b64decode(value).decode('utf-8')
        # Verifica se é texto legível (printable ASCII)
        if all(32 <= ord(c) <= 126 for c in decoded):
            return decoded
    except Exception:
        pass
    return value

def is_valid_alias(alias: str) -> bool:
    return bool(re.match(r'^[\w\s\-@.]+$', alias))

def safe_input(prompt: str = "", maxlen: Optional[int] = None, default: Optional[str] = None) -> str:
    """
    Faz input() e sanitiza o resultado; retorna default se string vazia e default fornecido.
    """
    try:
        raw = input(prompt)
    except KeyboardInterrupt:
        raise
    val = sanitize_text(raw, maxlen=maxlen)
    if not val and default is not None:
        return default
    return val

# clipboard helpers
def _try_copy_plain(text: str) -> bool:
    try:
        if HAVE_CLIP:
            pyperclip.copy(text)
            return True
    except Exception:
        pass
    try:
        if shutil.which("wl-copy"):
            p = subprocess.run(["wl-copy"], input=text.encode('utf-8'))
            return p.returncode == 0
    except Exception:
        pass
    try:
        if shutil.which("xclip"):
            p = subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode('utf-8'))
            return p.returncode == 0
    except Exception:
        pass
    try:
        if platform.system() == "Darwin" and shutil.which("pbcopy"):
            p = subprocess.run(["pbcopy"], input=text.encode('utf-8'))
            return p.returncode == 0
    except Exception:
        pass
    return False

def _try_get_clip_equals(text: str) -> bool:
    try:
        if HAVE_CLIP:
            return pyperclip.paste() == text
    except Exception:
        return False
    return False

def copy_with_timeout(text: str, timeout: int = CLIPBOARD_TIMEOUT) -> None:
    try:
        ok = _try_copy_plain(text)
        if not ok:
            print("(Aviso: clipboard indisponível — instale 'pyperclip' ou 'wl-copy/xclip/pbcopy')")
            return
        print(f"(Copiado para clipboard — limparei em {timeout}s)")
        def clear_clip():
            time.sleep(timeout)
            try:
                same = False
                if HAVE_CLIP:
                    same = _try_get_clip_equals(text)
                if same or not HAVE_CLIP:
                    _try_copy_plain('')
                    print("(Área de transferência limpa automaticamente)")
                else:
                    print("(Aviso: não foi possível verificar clipboard, limpe manualmente)")
            except Exception as e:
                print(f"(Erro ao limpar área de transferência: {e})")
        threading.Thread(target=clear_clip, daemon=True).start()
    except Exception as e:
        print(f"(Erro ao copiar para clipboard: {e})")

# ---------- KDF & AES ----------
def derive_key(combined: str, salt: bytes, length: int = DERIVED_KEY_LEN) -> bytes:
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

def aesgcm_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    nonce = secrets.token_bytes(NONCE_LEN)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct

def aesgcm_decrypt(nonce: bytes, ct: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, associated_data=None)

# -------------- GPG wrappers --------------
def _gpg_encrypt_bytes(plain_bytes: bytes, out_path: Path, passphrase: str) -> bool:
    """
    Encrypta os bytes usando gpg simétrico. Usa mkstemp + chmod 0o600 para
    diminuir janela de exposição do plaintext no filesystem e tenta sobrescrever
    o arquivo temporário antes de removê-lo (melhor esforço).
    """
    fd, tmp = tempfile.mkstemp()
    try:
        try:
            # garantir permissões restritas (somente dono)
            try:
                os.fchmod(fd, 0o600)
            except Exception:
                # em alguns sistemas fchmod pode falhar — tenta chmod no caminho
                try:
                    os.chmod(tmp, 0o600)
                except Exception:
                    pass

            # escrever os bytes plaintext e fechar o descritor (com fdopen)
            with os.fdopen(fd, 'wb') as tf:
                tf.write(plain_bytes)
                tf.flush()

            # preparar comando gpg (usa loopback para aceitar passphrase via stdin)
            cmd = [
                GPG_BIN, '--batch', '--yes', '--pinentry-mode', 'loopback',
                '--symmetric', '--cipher-algo', 'AES256',
                '--passphrase-fd', '0', '--output', str(out_path), tmp
            ]
            p = subprocess.run(cmd, input=(passphrase + "\n").encode(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # verificar retorno do gpg
            if p.returncode != 0:
                raise RuntimeError(p.stderr.decode(errors='ignore').strip())

            return True
        finally:
            # tentativa melhor-esforço de sobrescrever e remover o arquivo temporário
            try:
                # reabrir e sobrescrever com zeros — só se o arquivo existir
                with open(tmp, 'r+b') as f:
                    f.seek(0)
                    f.write(b'\x00' * os.path.getsize(tmp))
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                pass
            try:
                os.unlink(tmp)
            except Exception:
                pass
    except Exception:
        # garantir que o descritor não fique aberto caso exceção ocorra antes do fdopen
        try:
            os.close(fd)
        except Exception:
            pass
        raise

def _gpg_decrypt_to_bytes(vault_path: Path, passphrase: str) -> bytes:
    if not vault_path.exists():
        return b''
    cmd = [GPG_BIN, '--batch', '--yes', '--pinentry-mode', 'loopback', '--decrypt',
           '--passphrase-fd', '0', str(vault_path)]
    p = subprocess.run(cmd, input=(passphrase + "\n").encode(),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode(errors='ignore').strip())
    return p.stdout

# -------------- vault IO --------------
def load_vault(passphrase: str) -> Dict[str, Any]:
    ensure_vault_dir()
    if not VAULT_PATH.exists():
        return {}
    raw = _gpg_decrypt_to_bytes(VAULT_PATH, passphrase)
    return json.loads(raw.decode('utf-8')) if raw else {}

def save_vault(vobj: Dict[str, Any], passphrase: str) -> bool:
    ensure_vault_dir()
    plain = json.dumps(vobj, ensure_ascii=False, indent=2).encode('utf-8')
    return _gpg_encrypt_bytes(plain, VAULT_PATH, passphrase)

def create_backup(prefix: str = "vault.gpg.bak") -> Optional[Path]:
    """
    Cria backup do VAULT_PATH com prefixo e retorna o path criado.
    Usado tanto para backups automáticos quanto manuais.
    """
    if not VAULT_PATH.exists():
        return None
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    bak = VAULT_PATH.parent / f"{prefix}.{ts}"
    with open(VAULT_PATH, 'rb') as fsrc, open(bak, 'wb') as fdst:
        fdst.write(fsrc.read())
    # prune older
    backups = sorted(VAULT_PATH.parent.glob(f"{prefix}.*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in backups[BACKUP_KEEP:]:
        try:
            old.unlink()
        except Exception:
            pass
    return bak

def backup_vault_auto() -> None:
    create_backup("vault.gpg.bak")

# ---------------- helper para extras input ----------------
def prompt_extras_interactive(existing: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Loop interativo para inserir/editar pares chave/valor em extras.
    Retorna dict (padrão {} se vazio).
    """
    extras = dict(existing) if existing else {}
    print("\n--- Extras (opcional) ---")
    print("Insira pares chave=valor. Deixe em branco e pressione Enter quando terminar.")
    if extras:
        print("Extras atuais:")
        for k, v in extras.items():
            print(f" - {k}: {v}")
    while True:
        raw = safe_input("Chave (Enter p/ terminar): ").strip()
        if not raw:
            break
        key = sanitize_text(raw, maxlen=120)
        val = safe_input(f"Valor para '{key}': ")
        extras[key] = val
    return extras

# ---------------- operations (menu) ----------------
def op_change_master_password(vault: Dict[str, Any], old_passphrase: str) -> str:
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

def _pack_secret_and_extras(secret: str, extras: Optional[Dict[str, str]] = None) -> bytes:
    """
    Retorna bytes do payload JSON contendo 'secret' e 'extras' (mesmo que extras seja {}).
    """
    payload = {"secret": secret}
    if extras:
        payload["extras"] = extras
    else:
        payload["extras"] = {}
    return json.dumps(payload, ensure_ascii=False).encode('utf-8')

def _unpack_secret_and_extras(plaintext_bytes: bytes) -> Tuple[str, Dict[str, str]]:
    """
    Tenta interpretar plaintext_bytes como JSON {"secret":..., "extras":{...}}.
    Se não for JSON, assume que é apenas a senha e retorna (senha_str, {}).
    """
    try:
        text = plaintext_bytes.decode('utf-8')
    except Exception:
        # fallback: try latin-1 then as best-effort text
        try:
            text = plaintext_bytes.decode('latin-1')
        except Exception:
            return ("", {})
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "secret" in obj:
            extras = obj.get("extras", {}) or {}
            # ensure extras values are str
            if not isinstance(extras, dict):
                extras = {}
            extras = {str(k): str(v) for k, v in extras.items()}
            return (str(obj["secret"]), extras)
    except Exception:
        # not JSON — old format (plain secret)
        return (text, {})
    return (text, {})

def op_add(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Adicionar novo alias ---")
    alias = safe_input("Alias (nome identificador): ", maxlen=120)
    if not alias or not is_valid_alias(alias):
        print("Alias inválido.")
        return
    if alias in vault:
        print("Já existe um registro com esse alias.")
        return
    dica1_name = safe_input("Dica 1 (descrição): ", maxlen=120)
    dica2_name = safe_input("Dica 2 (descrição): ", maxlen=120)
    k1 = sanitize_text(safe_input("Valor Dica 1 (Enter p/ gerar): ")) or gen_dica_auto()
    k2 = sanitize_text(safe_input("Valor Dica 2 (Enter p/ gerar): ")) or gen_dica_auto()
    secret = getpass.getpass("Senha / secret: ")
    if not secret:
        print("Senha vazia; abortando.")
        return
    # extras interativo
    extras = prompt_extras_interactive()
    combined = k1 + "|" + k2
    salt = secrets.token_bytes(SALT_LEN)
    derived = derive_key(combined, salt)
    # pack secret + extras into JSON bytes, then encrypt
    payload_bytes = _pack_secret_and_extras(secret, extras)
    nonce, ct = aesgcm_encrypt(payload_bytes, derived)
    entry = {
        "meta": {"dica1_name": dica1_name or "Dica1",
                 "dica2_name": dica2_name or "Dica2",
                 "created": _now_ts()},
        "data": {"salt": binascii.hexlify(salt).decode(),
                 "nonce": binascii.hexlify(nonce).decode(),
                 "cipher_b64": base64.b64encode(ct).decode()}
    }
    # backup + salvar
    create_backup("vault.gpg.bak")
    vault[alias] = entry
    save_vault(vault, passphrase)
    print("\nADICIONADO:", alias)
    print(f"[{entry['meta']['dica1_name']}]: {k1}")
    print(f"[{entry['meta']['dica2_name']}]: {k2}")
    if extras:
        print("Extras adicionados:")
        for kk, vv in extras.items():
            print(f" - {kk}: {vv}")
    copy_with_timeout(secret)
    # tentar reduzir exposição
    secret = None
    derived = None
    combined = None
    payload_bytes = None
    gc.collect()

def op_get(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Recuperar alias ---")
    alias = safe_input("Alias: ", maxlen=120)
    if alias not in vault:
        print("Registro não encontrado.")
        return
    entry = vault[alias]
    meta = entry.get("meta", {})
    d1_name = meta.get("dica1_name", "Dica1")
    d2_name = meta.get("dica2_name", "Dica2")
    v1 = safe_input(f"Digite [{d1_name}]: ")
    v2 = safe_input(f"Digite [{d2_name}]: ")
    salt = binascii.unhexlify(entry["data"]["salt"])
    nonce = binascii.unhexlify(entry["data"]["nonce"])
    ct = base64.b64decode(entry["data"]["cipher_b64"])
    combined = v1 + "|" + v2
    derived = derive_key(combined, salt)
    try:
        plaintext = aesgcm_decrypt(nonce, ct, derived)
        secret, extras = _unpack_secret_and_extras(plaintext)
        print(f"\nAlias: {alias}")
        print(f"Senha: {secret}")
        if extras:
            print("\nExtras:")
            for k, val in extras.items():
                print(f" - {k}: {val}")
        copy_with_timeout(secret)
    except Exception:
        print("Dicas incorretas ou dados corrompidos.")
    finally:
        # reduzir exposição
        derived = None
        combined = None
        try:
            secret = None
        except Exception:
            pass
        gc.collect()

def op_list(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Aliases cadastrados ---")
    if not vault:
        print("(nenhum registro)")
        return
    for k in sorted(vault.keys(), key=lambda s: s.lower()):
        print("-", k)

def op_delete(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Excluir alias ---")
    alias = safe_input("Alias: ", maxlen=120)
    if not alias:
        print("É necessário informar um alias.")
        return
    if alias not in vault:
        print("Registro não encontrado.")
        return
    confirm = safe_input(f"Confirma remoção de '{alias}'? Digite o alias completo para confirmar: ", maxlen=120)
    if confirm != alias:
        print("Confirmação incorreta. Abortando.")
        return
    create_backup("vault.gpg.bak")
    del vault[alias]
    try:
        save_vault(vault, passphrase)
    except Exception as e:
        print("Erro ao salvar vault:", e)
        return
    print("Removido com sucesso.")

def op_edit(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Editar alias ---")
    alias = safe_input("Alias: ", maxlen=120)
    if not alias:
        print("É necessário informar um alias.")
        return
    if alias not in vault:
        print("Registro não encontrado.")
        return
    entry = vault[alias]
    meta = entry.get("meta", {})
    data = entry.get("data", {})
    d1_name = meta.get("dica1_name", "Dica1")
    d2_name = meta.get("dica2_name", "Dica2")
    v1 = safe_input(f"Digite [{d1_name}] atual: ")
    v2 = safe_input(f"Digite [{d2_name}] atual: ")
    try:
        salt = binascii.unhexlify(data["salt"])
        nonce = binascii.unhexlify(data["nonce"])
        ct = base64.b64decode(data["cipher_b64"])
        derived = derive_key(v1 + "|" + v2, salt)
        plaintext = aesgcm_decrypt(nonce, ct, derived)
        secret_old, extras_old = _unpack_secret_and_extras(plaintext)
    except Exception:
        print("Dicas incorretas ou dados corrompidos. Abortando.")
        return
    print("\nValores atuais:")
    print(f"Alias: {alias}")
    print(f"{d1_name}: {v1}")
    print(f"{d2_name}: {v2}")
    print(f"Senha atual: {secret_old}")
    if extras_old:
        print("Extras atuais:")
        for k, val in extras_old.items():
            print(f" - {k}: {val}")
    print("Deixe em branco para manter o valor atual.\n")
    new_d1_name = safe_input(f"Novo nome para [{d1_name}]: ", maxlen=120) or d1_name
    new_d2_name = safe_input(f"Novo nome para [{d2_name}]: ", maxlen=120) or d2_name
    new_v1 = safe_input(f"Novo valor para [{new_d1_name}]: ") or v1
    new_v2 = safe_input(f"Novo valor para [{new_d2_name}]: ") or v2
    new_secret = getpass.getpass("Nova senha (Enter para manter): ") or secret_old
    # editar extras?
    edit_extras = safe_input("Editar extras? (s/N): ").lower() == "s"
    if edit_extras:
        new_extras = prompt_extras_interactive(existing=extras_old)
    else:
        new_extras = extras_old or {}
    combined = new_v1 + "|" + new_v2
    salt = secrets.token_bytes(SALT_LEN)
    derived = derive_key(combined, salt)
    payload_bytes = _pack_secret_and_extras(new_secret, new_extras)
    nonce, ct = aesgcm_encrypt(payload_bytes, derived)
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
    create_backup("vault.gpg.bak")
    vault[alias] = entry
    try:
        save_vault(vault, passphrase)
    except Exception as e:
        print("Erro ao salvar alterações:", e)
        return
    print("\nAlias atualizado com sucesso.")
    print(f"[{entry['meta']['dica1_name']}]: {new_v1}")
    print(f"[{entry['meta']['dica2_name']}]: {new_v2}")
    print("Anote novamente esses valores.")
    # reduzir exposição
    try:
        secret_old = None
    except Exception:
        pass
    derived = None
    combined = None
    payload_bytes = None
    gc.collect()

def op_backup(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Backup manual do vault ---")
    ensure_vault_dir()
    if not VAULT_PATH.exists():
        print("Vault não existe. Nada a exportar.")
        return
    dest = create_backup("vault.gpg.manualbak")
    if dest:
        print("Backup criado:", dest)

def _parse_bak_ts(name: str) -> str:
    try:
        ts = name.rsplit('.', 1)[-1]
        dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return name

def op_restore(vault: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
    print("\n--- Restaurar backup ---")
    ensure_vault_dir()
    candidates: List[Path] = []
    for p in sorted(VAULT_DIR.glob("vault.gpg.bak.*"), key=lambda p: p.stat().st_mtime, reverse=True):
        candidates.append(p)
    for p in sorted(VAULT_DIR.glob("vault.gpg.manualbak.*"), key=lambda p: p.stat().st_mtime, reverse=True):
        candidates.append(p)
    if not candidates:
        print("Nenhum backup encontrado em:", VAULT_DIR)
        return vault
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
    if VAULT_PATH.exists():
        tmp_save = VAULT_PATH.parent / f"vault.gpg.pre_restore.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        try:
            with open(VAULT_PATH, 'rb') as fsrc, open(tmp_save, 'wb') as fdst:
                fdst.write(fsrc.read())
            print(f"Cópia do vault atual salva em: {tmp_save.name}")
        except Exception as e:
            print("Falha ao salvar cópia do vault atual:", e)
            return vault
    try:
        with open(chosen, 'rb') as fsrc, open(VAULT_PATH, 'wb') as fdst:
            fdst.write(fsrc.read())
    except Exception as e:
        print("Erro ao restaurar arquivo:", e)
        return vault
    try:
        new_vault = load_vault(passphrase)
        print("Backup restaurado com sucesso e cofre recarregado.")
        return new_vault
    except Exception as e:
        print("Backup restaurado, mas falha ao recarregar o cofre com a passphrase atual:", e)
        print("Se a passphrase for diferente para esse backup, utilize a opção de carregar manualmente.")
        return vault

# ---------------- UI / utilitários menores ----------------
def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def pause() -> None:
    input("\nPressione Enter para continuar...")

def header() -> None:
    print("Token Vault Secure - menu interativo")

def type_effect(text: str, delay: float = 0.02, newline: bool = True) -> None:
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
        print()

def print_banner(title: str = "Token Vault Secure", version: str = "") -> None:
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

# ---------------- menu / CLI ----------------
def menu_loop() -> None:
    header()
    passphrase = getpass.getpass("Passphrase do cofre (será solicitada): ")
    try:
        vault = load_vault(passphrase)
    except Exception as e:
        print("Erro ao abrir vault:", e)
        return
    while True:
        clear_screen()
        print_banner("Token Vault Secure", "v0.6.0")
        print("\nEscolha uma opção:")
        print("1 - Adicionar alias")
        print("2 - Recuperar alias")
        print("3 - Editar alias")
        print("4 - Excluir alias")
        print("5 - Listar aliases")
        print("6 - Backup manual")
        print("7 - Trocar senha mestra")
        print("8 - Restaurar backup")
        print("99 - Sair")
        opt = input("Opção: ").strip()
        if opt == "1":
            clear_screen(); op_add(vault, passphrase); pause()
        elif opt == "2":
            clear_screen(); op_get(vault, passphrase); pause()
        elif opt == "3":
            clear_screen(); op_edit(vault, passphrase); pause()
        elif opt == "4":
            op_delete(vault, passphrase); pause()
        elif opt == "5":
            clear_screen(); op_list(vault, passphrase); pause()
        elif opt == "6":
            op_backup(vault, passphrase); pause()
        elif opt == "7":
            passphrase = op_change_master_password(vault, passphrase); pause()
        elif opt == "8":
            clear_screen(); vault = op_restore(vault, passphrase); pause()
        elif opt == "99":
            type_effect("Saindo... até a próxima!", 0.02)
            break
        else:
            print("Opção inválida.")
            pause()

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Token Vault Secure — CLI ou modo interativo"
    )
    # Add
    sub = parser.add_subparsers(dest="command")
    add_p = sub.add_parser("add", help="Adicionar novo alias")
    add_p.add_argument("alias")
    add_p.add_argument("--dica1", help="Descrição da primeiro dica (Chave gerada automaticamente)")
    add_p.add_argument("--dica2", help="Descrição da segunda dica (Chave gerada automaticamente)")
    add_p.add_argument("--secret", help="Valor secreto")
    add_p.add_argument("--extras-json", help="Extras em JSON (ex: '{\"totp\":\"JBS...\",\"nota\":\"...\"}')")
    #Get
    get_p = sub.add_parser("get", help="Recuperar alias existente")
    get_p.add_argument("alias")
    get_p.add_argument("--dica1", help="Informa a chave referente a primeira dica (texto ou base64)")
    get_p.add_argument("--dica2", help="Informa a chave referente a segunda dica (texto ou base64)")
    # List
    sub.add_parser("list", help="Listar aliases armazenados")
    # Delete
    del_p = sub.add_parser("delete", help="Excluir um alias")
    del_p.add_argument("alias")
    # Backup and restore
    sub.add_parser("backup", help="Gera um backup manual")
    sub.add_parser("restore", help="Restaurar um backup existente")
    # Change master password
    sub.add_parser("changepass", help="Alterar a senha mestra do cofre")
    # Menu and version
    sub.add_parser("menu", help="Iniciar no modo interativo")
    parser.add_argument("--version", action="store_true", help="Exibe versão")
    return parser.parse_args()

def cli_mode(args: argparse.Namespace) -> None:
    try:
        passphrase = getpass.getpass("Senha mestra do cofre: ")
    except KeyboardInterrupt:
        print("\nInterrompido. Saindo.")
        return
    try:
        vault = load_vault(passphrase)
    except RuntimeError:
        print("Falha ao abrir vault: senha mestra incorreta ou vault corrompido.")
        return
    except Exception as e:
        print("Erro ao abrir vault:", e)
        return
    try:
        if args.command == "list":
            if not vault:
                print("Cofre vazio.")
                return
            print("\nAliases:")
            for lbl in vault.keys():
                print(f" - {lbl}")
        elif args.command == "add":
            alias = sanitize_text(args.alias)
            dica1_name = args.dica1 if args.dica1 is not None else safe_input("Nome para Dica 1 (ou Enter para 'Dica 1'): ")
            if not dica1_name:
                dica1_name = "Dica 1"
            dica2_name = args.dica2 if args.dica2 is not None else safe_input("Nome para Dica 2 (ou Enter para 'Dica 2'): ")
            if not dica2_name:
                dica2_name = "Dica 2"
            k1 = gen_dica_auto()
            k2 = gen_dica_auto()
            secret = args.secret or getpass.getpass("Valor secreto: ")
            # extras from CLI JSON
            extras = {}
            if getattr(args, "extras_json", None):
                try:
                    extras = json.loads(args.extras_json)
                    if not isinstance(extras, dict):
                        print(" --extras-json deve ser um objeto JSON (dicionário). Ignorando extras.")
                        extras = {}
                except Exception:
                    print("Não foi possível interpretar --extras-json como JSON. Ignorando extras.")
                    extras = {}
            else:
                # interactive prompt for extras (if desired)
                want = safe_input("Deseja adicionar extras (nota, totp, etc.)? (s/N): ").lower() == "s"
                if want:
                    extras = prompt_extras_interactive()
            combined = k1 + "|" + k2
            salt = secrets.token_bytes(SALT_LEN)
            derived = derive_key(combined, salt)
            payload_bytes = _pack_secret_and_extras(secret, extras)
            nonce, ct = aesgcm_encrypt(payload_bytes, derived)
            vault[alias] = {
                "meta": {"dica1_name": dica1_name, "dica2_name": dica2_name, "created": _now_ts()},
                "data": {"salt": binascii.hexlify(salt).decode(), "nonce": binascii.hexlify(nonce).decode(), "cipher_b64": base64.b64encode(ct).decode()}
            }
            save_vault(vault, passphrase)
            print(f"\nADICIONADO: {alias}")
            print(f"[{dica1_name}]: {k1}")
            print(f"[{dica2_name}]: {k2}")
            if extras:
                print("Extras adicionados:")
                for kk, vv in extras.items():
                    print(f" - {kk}: {vv}")
            copy_with_timeout(secret)
            # cleanup
            secret = None; derived = None; combined = None; payload_bytes = None
            gc.collect()
        elif args.command == "get":
            alias = args.alias
            entry = vault.get(alias)
            if not entry:
                print("Registro não encontrado.")
                return
            salt = binascii.unhexlify(entry["data"]["salt"])
            nonce = binascii.unhexlify(entry["data"]["nonce"])
            ct = base64.b64decode(entry["data"]["cipher_b64"])
            dica1_val = maybe_b64decode(args.dica1)
            dica2_val = maybe_b64decode(args.dica2)
            combined = (dica1_val or "") + "|" + (dica2_val or "")
            derived = derive_key(combined, salt)
            try:
                plaintext = aesgcm_decrypt(nonce, ct, derived)
                secret, extras = _unpack_secret_and_extras(plaintext)
                print(f"\nValor decifrado: {secret}")
                if extras:
                    print("\nExtras:")
                    for k, v in extras.items():
                        print(f" - {k}: {v}")
                copy_with_timeout(secret)
            except Exception:
                print("Falha ao decifrar — dicas incorretas?")
            finally:
                secret = None; derived = None; combined = None
                gc.collect()
        elif args.command == "delete":
            if args.alias not in vault:
                print("Alias não encontrada.")
                return
            confirm = input(f"Confirma exclusão de '{args.alias}'? (s/n): ").lower()
            if confirm == "s":
                del vault[args.alias]; save_vault(vault, passphrase); print("Excluída com sucesso.")
        elif args.command == "backup":
            op_backup(vault, passphrase)
        elif args.command == "restore":
            op_restore(vault, passphrase)
        elif args.command == "changepass":
            op_change_master_password(vault, passphrase)
        else:
            print("Comando desconhecido ou inválido.")
    except KeyboardInterrupt:
        print("\nInterrompido. Saindo.")
        return

def check_dependencies() -> None:
    # Verifica presença de gpg (evita erros tardios)
    if not shutil.which(GPG_BIN):
        print(f"ERRO: '{GPG_BIN}' não encontrado no PATH. Instale o GPG ou ajuste GPG_BIN.")
        sys.exit(1)

def main() -> None:
    check_dependencies()  # fail fast
    args = parse_args()
    if getattr(args, "version", False):
        print("Token Vault Secure - v0.6.0")
        return
    if not args.command or args.command == "menu":
        try:
            menu_loop()
        except KeyboardInterrupt:
            print("\nInterrompido. Saindo.")
    else:
        try:
            cli_mode(args)
        except KeyboardInterrupt:
            print("\nInterrompido. Saindo.")

if __name__ == "__main__":
    main()
