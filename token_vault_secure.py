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
DEFAULT_VAULT_NAME = "vault.gpg"

def resolve_vault_path(raw: Optional[str] = None) -> Path:
    """
    Descobre onde fica o arquivo do cofre. Prioridade:
      1) `raw` (flag --vault)
      2) variável de ambiente VAULT_PATH
      3) variável de ambiente VAULT_DIR  (+ vault.gpg)
      4) ~/.vault/vault.gpg
    Se o caminho for uma pasta (existente, ou terminado em / ou \\), o arquivo
    vault.gpg é criado dentro dela. A pasta do cofre é sempre a pasta do arquivo.
    """
    if not raw:
        raw = os.getenv("VAULT_PATH")
    if raw:
        p = Path(raw).expanduser()
        if p.is_dir() or raw.endswith(("/", os.sep)):
            p = p / DEFAULT_VAULT_NAME
    else:
        base = Path(os.getenv("VAULT_DIR") or (HOME / ".vault")).expanduser()
        p = base / DEFAULT_VAULT_NAME
    # abspath (e não resolve) para não seguir symlink do arquivo do cofre
    return Path(os.path.abspath(p))

VAULT_PATH = resolve_vault_path()
VAULT_DIR = VAULT_PATH.parent

def configure_vault_path(raw: Optional[str] = None) -> None:
    """Reconfigura o local do cofre (usado após ler a flag --vault)."""
    global VAULT_PATH, VAULT_DIR
    VAULT_PATH = resolve_vault_path(raw)
    VAULT_DIR = VAULT_PATH.parent

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

SEPARATOR = "\x1e"

# ---------------- helpers ----------------
_ANSI_ESC_RE = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]|\x1B\[[0-9;]*[A-Za-z]')

def ensure_vault_dir() -> None:
    """Cria a pasta do cofre se não existir. Só aplica chmod 700 na pasta pelo programa."""
    if VAULT_DIR.exists():
        return
    VAULT_DIR.mkdir(mode=0o700, parents=True)
    try:
        VAULT_DIR.chmod(0o700)
    except Exception:
        pass

def _chmod_private(path: Path) -> None:
    """Deixa o arquivo legível só pelo dono (melhor esforço; no-op no Windows
    e em pendrive FAT/exFAT)."""
    try:
        path.chmod(0o600)
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
class KdfUnavailable(RuntimeError):
    """O KDF exigido pela entrada não está disponível nesta máquina
    (ex.: entrada criada com Argon2id, mas 'argon2-cffi' não instalado).
    Tem classe própria para NÃO ser engolida pelo 'except Exception' genérico
    e virar a mensagem enganosa de 'dicas incorretas'."""

def normalize_dica(value: Optional[str]) -> str:
    """Normalização ÚNICA da dica. Usada em TODOS os caminhos (add/get,
    interativo/CLI) para a mesma dica gerar sempre a mesma chave."""
    return sanitize_text(value or "")

def _combined_from_dicas(d1: str, d2: str) -> str:
    return normalize_dica(d1) + SEPARATOR + normalize_dica(d2)

def current_kdf_params() -> Dict[str, Any]:
    """Descritor do KDF para NOVAS entradas, conforme o ambiente atual."""
    if USE_ARGON2:
        return {"algo": "argon2id", "time": ARGON2_TIME, "mem": ARGON2_MEM,
                "par": ARGON2_PAR, "len": DERIVED_KEY_LEN}
    return {"algo": "pbkdf2-sha256", "iters": PBKDF2_ITERS, "len": DERIVED_KEY_LEN}

def derive_key_with(combined: str, salt: bytes, kdf: Dict[str, Any]) -> bytes:
    """Deriva a chave usando EXATAMENTE o KDF/params descritos em `kdf`."""
    pwd = combined.encode('utf-8')
    algo = kdf.get("algo")
    length = int(kdf.get("len", DERIVED_KEY_LEN))
    if algo == "argon2id":
        if not USE_ARGON2:
            raise KdfUnavailable(
                "Esta entrada foi criada com Argon2id, mas o pacote 'argon2-cffi' "
                "não está instalado nesta máquina. Rode: pip install argon2-cffi"
            )
        return hash_secret_raw(secret=pwd, salt=salt,
                               time_cost=int(kdf["time"]), memory_cost=int(kdf["mem"]),
                               parallelism=int(kdf["par"]), hash_len=length, type=Type.ID)
    elif algo == "pbkdf2-sha256":
        k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt,
                       iterations=int(kdf["iters"]), backend=default_backend())
        return k.derive(pwd)
    raise KdfUnavailable(f"KDF desconhecido na entrada: {algo}")

def _legacy_kdf_candidates() -> List[Dict[str, Any]]:
    """KDFs a tentar em entradas ANTIGAS (sem campo 'kdf'). O AES-GCM é
    autenticado, então uma chave errada falha limpo — dá pra tentar em ordem."""
    cands: List[Dict[str, Any]] = []
    if USE_ARGON2:
        cands.append({"algo": "argon2id", "time": ARGON2_TIME, "mem": ARGON2_MEM,
                      "par": ARGON2_PAR, "len": DERIVED_KEY_LEN})
    cands.append({"algo": "pbkdf2-sha256", "iters": PBKDF2_ITERS, "len": DERIVED_KEY_LEN})
    return cands

def aesgcm_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    nonce = secrets.token_bytes(NONCE_LEN)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct

def aesgcm_decrypt(nonce: bytes, ct: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, associated_data=None)

def encrypt_entry_data(payload_bytes: bytes, d1: str, d2: str) -> Dict[str, Any]:
    """Cifra o payload de uma NOVA entrada e devolve o bloco 'data' completo,
    JÁ com o descritor de KDF salvo."""
    kdf = current_kdf_params()
    salt = secrets.token_bytes(SALT_LEN)
    derived = derive_key_with(_combined_from_dicas(d1, d2), salt, kdf)
    nonce, ct = aesgcm_encrypt(payload_bytes, derived)
    return {
        "salt": binascii.hexlify(salt).decode(),
        "nonce": binascii.hexlify(nonce).decode(),
        "cipher_b64": base64.b64encode(ct).decode(),
        "kdf": kdf,
    }

def decrypt_entry(entry: Dict[str, Any], d1: str, d2: str) -> bytes:
    """Decifra o payload. Entrada nova: usa o 'kdf' salvo. Entrada antiga
    (sem 'kdf'): tenta os candidatos — o GCM valida qual é o certo."""
    data = entry["data"]
    salt = binascii.unhexlify(data["salt"])
    nonce = binascii.unhexlify(data["nonce"])
    ct = base64.b64decode(data["cipher_b64"])
    combined = _combined_from_dicas(d1, d2)
    kdf = data.get("kdf")
    if kdf:
        return aesgcm_decrypt(nonce, ct, derive_key_with(combined, salt, kdf))
    last_err: Optional[Exception] = None
    for cand in _legacy_kdf_candidates():
        try:
            return aesgcm_decrypt(nonce, ct, derive_key_with(combined, salt, cand))
        except Exception as e:
            last_err = e
    raise last_err if last_err else RuntimeError("Falha ao decifrar.")

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
    # leitura não cria pasta nenhuma: cofre inexistente = cofre vazio
    if not VAULT_PATH.exists():
        return {}
    raw = _gpg_decrypt_to_bytes(VAULT_PATH, passphrase)
    return json.loads(raw.decode('utf-8')) if raw else {}

def save_vault(vobj: Dict[str, Any], passphrase: str) -> bool:
    ensure_vault_dir()
    plain = json.dumps(vobj, ensure_ascii=False, indent=2).encode('utf-8')
    ok = _gpg_encrypt_bytes(plain, VAULT_PATH, passphrase)
    _chmod_private(VAULT_PATH)
    return ok

def _backup_prefix(kind: str) -> str:
    """Prefixo derivado do NOME do cofre, para dois cofres na mesma pasta
    (a.gpg e b.gpg) não misturarem nem apagarem os backups um do outro."""
    return f"{VAULT_PATH.name}.{kind}"

def _list_backups(kind: str) -> List[Path]:
    """Backups de um tipo ('bak' ou 'manualbak'), mais recentes primeiro.
    Filtra por nome (e não por glob) para nomes de arquivo com [ ] * ?."""
    prefix = _backup_prefix(kind) + "."
    if not VAULT_DIR.exists():
        return []
    found = [p for p in VAULT_DIR.iterdir() if p.is_file() and p.name.startswith(prefix)]
    return sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)

def create_backup(kind: str = "bak") -> Optional[Path]:
    """
    Cria backup do VAULT_PATH ('bak' = automático, 'manualbak' = manual) e
    retorna o path criado.
    """
    if not VAULT_PATH.exists():
        return None
    # microssegundos no nome: duas operações no mesmo segundo não se sobrescrevem
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    bak = VAULT_DIR / f"{_backup_prefix(kind)}.{ts}"
    with open(VAULT_PATH, 'rb') as fsrc, open(bak, 'wb') as fdst:
        fdst.write(fsrc.read())
    _chmod_private(bak)
    # prune older
    for old in _list_backups(kind)[BACKUP_KEEP:]:
        try:
            old.unlink()
        except Exception:
            pass
    return bak

def backup_vault_auto() -> None:
    create_backup("bak")

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
    print("\n--- Novo registro ---")
    alias = safe_input("Nome do registro (ex.: servidor-a): ", maxlen=120)
    if not alias or not is_valid_alias(alias):
        print("Nome inválido. Use letras, números, espaço e os símbolos - _ @ .")
        return
    if alias in vault:
        print("Já existe um registro com esse nome.")
        return
    dica1_name = safe_input("Dica 1 (descrição): ", maxlen=120)
    dica2_name = safe_input("Dica 2 (descrição): ", maxlen=120)
    k1 = sanitize_text(safe_input("Valor Dica 1 (Enter p/ gerar): ")) or gen_dica_auto()
    k2 = sanitize_text(safe_input("Valor Dica 2 (Enter p/ gerar): ")) or gen_dica_auto()
    secret = getpass.getpass("Segredo (senha, token, chave de API): ")
    if not secret:
        print("Segredo vazio; abortando.")
        return
    # extras interativo
    extras = prompt_extras_interactive()
    # pack secret + extras into JSON bytes, then encrypt (KDF fica gravado na entrada)
    payload_bytes = _pack_secret_and_extras(secret, extras)
    entry = {
        "meta": {"dica1_name": dica1_name or "Dica1",
                 "dica2_name": dica2_name or "Dica2",
                 "created": _now_ts()},
        "data": encrypt_entry_data(payload_bytes, k1, k2)
    }
    # backup + salvar
    create_backup("bak")
    vault[alias] = entry
    save_vault(vault, passphrase)
    print("\nRegistro criado:", alias)
    print(f"[{entry['meta']['dica1_name']}]: {k1}")
    print(f"[{entry['meta']['dica2_name']}]: {k2}")
    if extras:
        print("Extras adicionados:")
        for kk, vv in extras.items():
            print(f" - {kk}: {vv}")
    copy_with_timeout(secret)
    # tentar reduzir exposição
    secret = None
    payload_bytes = None
    gc.collect()

def op_get(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Abrir registro ---")
    alias = safe_input("Nome do registro: ", maxlen=120)
    if alias not in vault:
        print("Registro não encontrado.")
        return
    entry = vault[alias]
    meta = entry.get("meta", {})
    d1_name = meta.get("dica1_name", "Dica1")
    d2_name = meta.get("dica2_name", "Dica2")
    v1 = safe_input(f"Digite [{d1_name}]: ")
    v2 = safe_input(f"Digite [{d2_name}]: ")
    try:
        plaintext = decrypt_entry(entry, v1, v2)
        secret, extras = _unpack_secret_and_extras(plaintext)
        print(f"\nRegistro: {alias}")
        print(f"Segredo: {secret}")
        if extras:
            print("\nExtras:")
            for k, val in extras.items():
                print(f" - {k}: {val}")
        copy_with_timeout(secret)
    except KdfUnavailable as e:
        print(f"\n{e}")
    except Exception:
        print("Dicas incorretas ou dados corrompidos.")
    finally:
        # reduzir exposição
        try:
            secret = None
        except Exception:
            pass
        gc.collect()

def op_list(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Registros cadastrados ---")
    if not vault:
        print("(nenhum registro)")
        return
    for k in sorted(vault.keys(), key=lambda s: s.lower()):
        print("-", k)

def op_delete(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Excluir registro ---")
    alias = safe_input("Nome do registro: ", maxlen=120)
    if not alias:
        print("É necessário informar o nome do registro.")
        return
    if alias not in vault:
        print("Registro não encontrado.")
        return
    confirm = safe_input(f"Para confirmar a exclusão de '{alias}', digite o nome completo: ", maxlen=120)
    if confirm != alias:
        print("Confirmação incorreta. Abortando.")
        return
    create_backup("bak")
    del vault[alias]
    try:
        save_vault(vault, passphrase)
    except Exception as e:
        print("Erro ao salvar o cofre:", e)
        return
    print("Registro excluído.")

def op_edit(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Editar registro ---")
    alias = safe_input("Nome do registro: ", maxlen=120)
    if not alias:
        print("É necessário informar o nome do registro.")
        return
    if alias not in vault:
        print("Registro não encontrado.")
        return
    entry = vault[alias]
    meta = entry.get("meta", {})
    d1_name = meta.get("dica1_name", "Dica1")
    d2_name = meta.get("dica2_name", "Dica2")
    v1 = safe_input(f"Digite [{d1_name}] atual: ")
    v2 = safe_input(f"Digite [{d2_name}] atual: ")
    try:
        plaintext = decrypt_entry(entry, v1, v2)
        secret_old, extras_old = _unpack_secret_and_extras(plaintext)
    except KdfUnavailable as e:
        print(f"\n{e}")
        return
    except Exception:
        print("Dicas incorretas ou dados corrompidos. Abortando.")
        return
    print("\nValores atuais:")
    print(f"Registro: {alias}")
    print(f"{d1_name}: {v1}")
    print(f"{d2_name}: {v2}")
    print(f"Segredo atual: {secret_old}")
    if extras_old:
        print("Extras atuais:")
        for k, val in extras_old.items():
            print(f" - {k}: {val}")
    print("Deixe em branco para manter o valor atual.\n")
    new_d1_name = safe_input(f"Novo nome para [{d1_name}]: ", maxlen=120) or d1_name
    new_d2_name = safe_input(f"Novo nome para [{d2_name}]: ", maxlen=120) or d2_name
    new_v1 = safe_input(f"Novo valor para [{new_d1_name}]: ") or v1
    new_v2 = safe_input(f"Novo valor para [{new_d2_name}]: ") or v2
    new_secret = getpass.getpass("Novo segredo (Enter para manter): ") or secret_old
    # editar extras?
    edit_extras = safe_input("Editar extras? (s/N): ").lower() == "s"
    if edit_extras:
        new_extras = prompt_extras_interactive(existing=extras_old)
    else:
        new_extras = extras_old or {}
    payload_bytes = _pack_secret_and_extras(new_secret, new_extras)
    entry = {
        "meta": {
            "dica1_name": new_d1_name,
            "dica2_name": new_d2_name,
            "created": meta.get("created", _now_ts()),
            "updated": _now_ts()
        },
        "data": encrypt_entry_data(payload_bytes, new_v1, new_v2)
    }
    create_backup("bak")
    vault[alias] = entry
    try:
        save_vault(vault, passphrase)
    except Exception as e:
        print("Erro ao salvar alterações:", e)
        return
    print("\nRegistro atualizado com sucesso.")
    print(f"[{entry['meta']['dica1_name']}]: {new_v1}")
    print(f"[{entry['meta']['dica2_name']}]: {new_v2}")
    print("Anote novamente esses valores.")
    # reduzir exposição
    secret_old = None
    payload_bytes = None
    gc.collect()

def op_backup(vault: Dict[str, Any], passphrase: str) -> None:
    print("\n--- Criar backup agora ---")
    if not VAULT_PATH.exists():
        print("Cofre não encontrado. Nada para copiar.")
        return
    dest = create_backup("manualbak")
    if dest:
        print("Backup criado:", dest)

def _parse_bak_ts(name: str) -> str:
    try:
        ts = name.rsplit('.', 1)[-1][:14]  # ignora os microssegundos
        dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return name

def op_restore(vault: Dict[str, Any], passphrase: str) -> Dict[str, Any]:
    print("\n--- Restaurar backup ---")
    candidates: List[Tuple[Path, str]] = (
        [(p, "automático") for p in _list_backups("bak")]
        + [(p, "manual") for p in _list_backups("manualbak")]
    )
    candidates.sort(key=lambda c: c[0].stat().st_mtime, reverse=True)
    if not candidates:
        print("Nenhum backup encontrado em:", VAULT_DIR)
        return vault
    print("Backups encontrados (mais recentes primeiro):")
    for i, (p, kind) in enumerate(candidates, start=1):
        print(f"{i:2d}. {_parse_bak_ts(p.name)}  ({kind})")
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
    chosen, kind = candidates[idx]
    pretty_chosen = _parse_bak_ts(chosen.name)
    confirm = sanitize_text(input(f"Restaurar o backup {kind} de {pretty_chosen}? Digite SIM para confirmar: ")).strip()
    if confirm.upper() != "SIM":
        print("Restauração não confirmada. Abortando.")
        return vault
    if VAULT_PATH.exists():
        tmp_save = VAULT_DIR / f"{VAULT_PATH.name}.pre_restore.{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        try:
            with open(VAULT_PATH, 'rb') as fsrc, open(tmp_save, 'wb') as fdst:
                fdst.write(fsrc.read())
            _chmod_private(tmp_save)
            print(f"Cópia do cofre atual salva em: {tmp_save.name}")
        except Exception as e:
            print("Falha ao salvar cópia do cofre atual:", e)
            return vault
    try:
        ensure_vault_dir()
        with open(chosen, 'rb') as fsrc, open(VAULT_PATH, 'wb') as fdst:
            fdst.write(fsrc.read())
        _chmod_private(VAULT_PATH)
    except Exception as e:
        print("Erro ao restaurar arquivo:", e)
        return vault
    try:
        new_vault = load_vault(passphrase)
        print("Backup restaurado com sucesso e cofre recarregado.")
        return new_vault
    except Exception as e:
        print("Backup restaurado, mas não abriu com a senha mestra atual:", e)
        print("Se esse backup usa outra senha mestra, feche o programa e abra de novo com ela.")
        return vault

# ---------------- UI / utilitários menores ----------------
def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def pause() -> None:
    input("\nPressione Enter para continuar...")

def header() -> None:
    print("Token Vault Secure - menu interativo")
    print(f"Cofre: {VAULT_PATH}")

def ask_master_passphrase(prompt: str = "Senha mestra do cofre: ") -> Optional[str]:
    """
    Cofre existente: pede a senha mestra uma vez.
    Cofre NOVO (arquivo ainda não existe): avisa onde será criado e pede a
    senha duas vezes — um erro de digitação aqui trancaria o cofre para sempre,
    e um --vault com caminho errado cairia silenciosamente num cofre novo.
    Retorna None se a confirmação falhar.
    """
    if VAULT_PATH.exists():
        return getpass.getpass(prompt)
    print(f"Cofre novo — será criado em: {VAULT_PATH}")
    p1 = getpass.getpass("Defina a senha mestra: ")
    p2 = getpass.getpass("Confirme a senha mestra: ")
    if not p1 or p1 != p2:
        print("Senhas não conferem ou vazias.")
        return None
    return p1

def open_vault(passphrase: str) -> Optional[Dict[str, Any]]:
    """Abre o cofre com mensagens amigáveis (a mesma no menu e no CLI).
    Retorna None se não conseguir abrir."""
    try:
        return load_vault(passphrase)
    except RuntimeError:
        print("Falha ao abrir o cofre: senha mestra incorreta ou cofre corrompido.")
    except Exception as e:
        print("Erro ao abrir o cofre:", e)
    return None

def type_effect(text: str, delay: float = 0.02, newline: bool = True) -> None:
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
        print()

def print_banner(title: str = "Token Vault Secure") -> None:
    frases = [
        "A segurança começa na simplicidade.",
        "Sem distrações, só propósito.",
        "Tudo sob controle — de forma discreta.",
        "Cada bit no seu devido lugar.",
        "Feito por quem gosta de ver as engrenagens girarem."
    ]
    use_color = False
    t = title
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
    passphrase = ask_master_passphrase()
    if passphrase is None:
        return
    vault = open_vault(passphrase)
    if vault is None:
        return
    while True:
        clear_screen()
        print_banner("Token Vault Secure")
        print(f"Cofre: {VAULT_PATH}")
        print("\nEscolha uma opção:")
        print("\nRegistros")
        print("  1 - Listar")
        print("  2 - Abrir")
        print("  3 - Novo")
        print("  4 - Editar")
        print("  5 - Excluir")
        print("\nCofre")
        print("  6 - Criar backup agora")
        print("  7 - Restaurar backup")
        print("  8 - Trocar senha mestra")
        print("\n  0 - Sair")
        opt = input("\nOpção: ").strip()
        if opt == "1":
            clear_screen(); op_list(vault, passphrase); pause()
        elif opt == "2":
            clear_screen(); op_get(vault, passphrase); pause()
        elif opt == "3":
            clear_screen(); op_add(vault, passphrase); pause()
        elif opt == "4":
            clear_screen(); op_edit(vault, passphrase); pause()
        elif opt == "5":
            op_delete(vault, passphrase); pause()
        elif opt == "6":
            op_backup(vault, passphrase); pause()
        elif opt == "7":
            clear_screen(); vault = op_restore(vault, passphrase); pause()
        elif opt == "8":
            passphrase = op_change_master_password(vault, passphrase); pause()
        elif opt == "0":
            type_effect("Saindo... até a próxima!", 0.02)
            break
        else:
            print("Opção inválida.")
            pause()

def parse_args() -> argparse.Namespace:
    # Opções comuns: valem antes OU depois do subcomando
    # (default=SUPPRESS evita o subparser sobrescrever o valor do parser principal)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--vault", metavar="CAMINHO", default=argparse.SUPPRESS,
        help="Arquivo (ou pasta) do cofre. Padrão: variável VAULT_PATH, "
             "senão ~/.vault/vault.gpg"
    )
    parser = argparse.ArgumentParser(
        description="Token Vault Secure — CLI ou modo interativo",
        parents=[common]
    )
    # Add
    sub = parser.add_subparsers(dest="command")
    add_p = sub.add_parser("add", help="Adicionar novo registro", parents=[common])
    add_p.add_argument("nome")
    add_p.add_argument("--dica1", help="Descrição da primeiro dica (Chave gerada automaticamente)")
    add_p.add_argument("--dica2", help="Descrição da segunda dica (Chave gerada automaticamente)")
    add_p.add_argument("--segredo", help="Valor do segredo")
    add_p.add_argument("--extras-json", help="Extras em JSON (ex: '{\"totp\":\"JBS...\",\"nota\":\"...\"}')")
    #Get
    get_p = sub.add_parser("get", help="Abrir registro existente", parents=[common])
    get_p.add_argument("nome")
    get_p.add_argument("--dica1", help="Informa a chave referente a primeira dica")
    get_p.add_argument("--dica2", help="Informa a chave referente a segunda dica")
    # List
    sub.add_parser("list", help="Listar registros", parents=[common])
    # Delete
    del_p = sub.add_parser("delete", help="Excluir um registro", parents=[common])
    del_p.add_argument("nome")
    # Backup and restore
    sub.add_parser("backup", help="Gera um backup manual", parents=[common])
    sub.add_parser("restore", help="Restaurar um backup existente", parents=[common])
    # Change master password
    sub.add_parser("changepass", help="Alterar a senha mestra do cofre", parents=[common])
    # Menu
    sub.add_parser("menu", help="Iniciar no modo interativo", parents=[common])
    return parser.parse_args()

def cli_mode(args: argparse.Namespace) -> None:
    # Só 'add' e 'restore' podem trabalhar com cofre que ainda não existe.
    # Nos demais, um cofre ausente quase sempre é caminho errado em --vault.
    if args.command not in ("add", "restore") and not VAULT_PATH.exists():
        print(f"Cofre não encontrado em: {VAULT_PATH}")
        print("Confira o caminho (--vault / VAULT_PATH) ou crie um com o comando 'add'.")
        return
    try:
        passphrase = ask_master_passphrase()
    except KeyboardInterrupt:
        print("\nInterrompido. Saindo.")
        return
    if passphrase is None:
        return
    vault = open_vault(passphrase)
    if vault is None:
        return
    try:
        if args.command == "list":
            if not vault:
                print("Cofre vazio.")
                return
            print("\nRegistros:")
            for lbl in vault.keys():
                print(f" - {lbl}")
        elif args.command == "add":
            alias = sanitize_text(args.nome)
            dica1_name = args.dica1 if args.dica1 is not None else safe_input("Nome para Dica 1 (ou Enter para 'Dica 1'): ")
            if not dica1_name:
                dica1_name = "Dica 1"
            dica2_name = args.dica2 if args.dica2 is not None else safe_input("Nome para Dica 2 (ou Enter para 'Dica 2'): ")
            if not dica2_name:
                dica2_name = "Dica 2"
            k1 = gen_dica_auto()
            k2 = gen_dica_auto()
            secret = args.segredo or getpass.getpass("Segredo (senha, token, chave de API): ")
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
            payload_bytes = _pack_secret_and_extras(secret, extras)
            vault[alias] = {
                "meta": {"dica1_name": dica1_name, "dica2_name": dica2_name, "created": _now_ts()},
                "data": encrypt_entry_data(payload_bytes, k1, k2)
            }
            save_vault(vault, passphrase)
            print(f"\nRegistro criado: {alias}")
            print(f"[{dica1_name}]: {k1}")
            print(f"[{dica2_name}]: {k2}")
            if extras:
                print("Extras adicionados:")
                for kk, vv in extras.items():
                    print(f" - {kk}: {vv}")
            copy_with_timeout(secret)
            # cleanup
            secret = None; payload_bytes = None
            gc.collect()
        elif args.command == "get":
            alias = args.nome
            entry = vault.get(alias)
            if not entry:
                print("Registro não encontrado.")
                return
            try:
                plaintext = decrypt_entry(entry, args.dica1 or "", args.dica2 or "")
                secret, extras = _unpack_secret_and_extras(plaintext)
                print(f"\nSegredo: {secret}")
                if extras:
                    print("\nExtras:")
                    for k, v in extras.items():
                        print(f" - {k}: {v}")
                copy_with_timeout(secret)
            except KdfUnavailable as e:
                print(f"\n{e}")
            except Exception:
                print("Falha ao decifrar — dicas incorretas?")
            finally:
                secret = None
                gc.collect()
        elif args.command == "delete":
            if args.nome not in vault:
                print("Registro não encontrado.")
                return
            confirm = safe_input(f"Para confirmar a exclusão de '{args.nome}', digite o nome completo: ", maxlen=120)
            if confirm != args.nome:
                print("Confirmação incorreta. Abortando.")
                return
            create_backup("bak")
            del vault[args.nome]; save_vault(vault, passphrase); print("Registro excluído.")
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
    configure_vault_path(getattr(args, "vault", None))
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
