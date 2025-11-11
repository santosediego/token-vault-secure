#!/usr/bin/env python3
import os
import json
import base64
import getpass
from cryptography.fernet import Fernet
from pathlib import Path

VAULT_FILE = Path.home() / ".token_vault.json"

# ------------------------
# Funções utilitárias
# ------------------------
def gerar_chave(passphrase: str) -> bytes:
    """Gera uma chave derivada da passphrase."""
    return base64.urlsafe_b64encode(passphrase.encode().ljust(32, b"0")[:32])

def carregar_vault(passphrase: str) -> dict:
    """Carrega e descriptografa o cofre."""
    if not VAULT_FILE.exists():
        return {}
    with open(VAULT_FILE, "rb") as f:
        data = f.read()
    fernet = Fernet(gerar_chave(passphrase))
    try:
        decrypted = fernet.decrypt(data).decode()
        return json.loads(decrypted)
    except Exception:
        print("❌ Passphrase incorreta ou arquivo corrompido.")
        return None

def salvar_vault(vault: dict, passphrase: str):
    """Salva e criptografa o cofre."""
    fernet = Fernet(gerar_chave(passphrase))
    encrypted = fernet.encrypt(json.dumps(vault).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

def gerar_token() -> str:
    """Gera uma chave segura."""
    return base64.urlsafe_b64encode(os.urandom(6)).decode()[:8]

# ------------------------
# Operações principais
# ------------------------
def adicionar_senha(vault, passphrase):
    print("\n--- Adicionar nova senha ---")
    label = input("Nome ou label: ").strip()
    if label in vault:
        print("❌ Já existe um registro com esse nome.")
        return

    dica1 = input("Dica 1: ").strip()
    dica2 = input("Dica 2: ").strip()

    key_auto = input("Gerar chave automaticamente? [S/n]: ").strip().lower()
    if key_auto in ("", "s", "sim"):
        key = gerar_token()
    else:
        key = input("Informe a chave manualmente: ").strip()

    senha = getpass.getpass("Senha: ")

    vault[label] = {
        "dica1": dica1,
        "dica2": dica2,
        "key": key,
        "senha": senha,
    }

    salvar_vault(vault, passphrase)
    print("\n✅ Registro adicionado com sucesso!")
    print(f"Label: {label}")
    print(f"[{dica1}]: {key}")
    print(f"[{dica2}]: {senha}\n")

def buscar_senha(vault):
    print("\n--- Buscar senha ---")
    label = input("Informe o label: ").strip()
    if label not in vault:
        print("❌ Nenhum registro encontrado com esse nome.")
        return

    registro = vault[label]
    print(f"\nDigite [{registro['dica1']}]: ", end="")
    dica1_valor = input().strip()
    print(f"Digite [{registro['dica2']}]: ", end="")
    dica2_valor = input().strip()

    if dica1_valor == registro["key"] and dica2_valor == registro["senha"]:
        print(f"\n🔐 Label: {label}")
        print(f"Senha: {registro['senha']}")
    else:
        print("❌ Dicas incorretas.")

def excluir_senha(vault, passphrase):
    print("\n--- Excluir senha ---")
    label = input("Informe o label: ").strip()
    if label not in vault:
        print("❌ Nenhum registro encontrado.")
        return

    confirm = input(f"Tem certeza que deseja excluir '{label}'? (digite o nome completo para confirmar): ")
    if confirm == label:
        del vault[label]
        salvar_vault(vault, passphrase)
        print("✅ Registro excluído com sucesso.")
    else:
        print("❌ Confirmação incorreta. Operação cancelada.")

def listar_senhas(vault):
    print("\n--- Lista de labels ---")
    if not vault:
        print("📭 Nenhum registro encontrado.")
        return
    for label in vault:
        print(f"- {label}")

# ------------------------
# Menu principal
# ------------------------
def menu():
    print("\n===== Token Vault =====")
    print("1 - Adicionar senha")
    print("2 - Buscar senha")
    print("3 - Excluir senha")
    print("4 - Listar descrições")
    print("5 - Sair")

def main():
    print("🔐 Acesso ao Token Vault 🔐")
    passphrase = getpass.getpass("Passphrase do cofre: ")
    vault = carregar_vault(passphrase)
    if vault is None:
        return

    while True:
        menu()
        opcao = input("Escolha uma opção: ").strip()

        if opcao == "1":
            adicionar_senha(vault, passphrase)
        elif opcao == "2":
            buscar_senha(vault)
        elif opcao == "3":
            excluir_senha(vault, passphrase)
        elif opcao == "4":
            listar_senhas(vault)
        elif opcao == "5":
            print("👋 Saindo com segurança.")
            break
        else:
            print("❌ Opção inválida.")

if __name__ == "__main__":
    main()
