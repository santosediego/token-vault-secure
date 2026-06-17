# Token Vault Secure 🔐

Cofre local para armazenamento seguro de credenciais, tokens, chaves de API e outras informações sensíveis.

O projeto foi desenvolvido como estudo de criptografia aplicada, gerenciamento seguro de segredos e desenvolvimento de aplicações de linha de comando em Python.

Diferente de gerenciadores de senhas tradicionais, cada registro armazenado possui sua própria camada de proteção criptográfica, baseada em informações independentes de recuperação definidas no momento da criação.

---

## ✨ Características

* Interface em linha de comando (CLI)
* Menu interativo para uso simplificado
* Criptografia autenticada com AES-GCM
* Derivação de chaves utilizando Argon2 (com fallback para PBKDF2)
* Armazenamento persistente protegido por GPG
* Backups automáticos e manuais
* Troca de senha mestra
* Limpeza automática da área de transferência após recuperação de segredos
* Suporte a campos adicionais (extras) para cada registro
* Recuperação e restauração de backups
* Geração automática de chaves auxiliares

---

## 🏗️ Arquitetura de Proteção

O sistema utiliza múltiplas camadas de proteção para reduzir pontos únicos de falha.

### Camada 1 — Cofre Principal

Todo o conteúdo do cofre é armazenado em um arquivo criptografado utilizando GPG.

O acesso ao arquivo requer a senha mestra definida pelo usuário.

### Camada 2 — Proteção Individual por Registro

Cada segredo armazenado possui sua própria chave criptográfica derivada a partir de duas informações independentes de recuperação.

Essas informações são utilizadas para gerar uma chave exclusiva através de Argon2 (ou PBKDF2 como fallback), protegendo individualmente cada registro.

Dessa forma, o acesso ao arquivo do cofre não implica necessariamente acesso aos segredos armazenados.

---

## 📦 Estrutura dos Dados

Cada registro contém:

* Alias identificador
* Metadados de recuperação
* Material criptográfico
* Segredo principal
* Campos adicionais opcionais

Exemplos de uso dos campos extras:

* Chaves TOTP
* Notas privadas
* URLs de serviços
* Informações complementares de autenticação

---

## 🖥️ Modos de Utilização

### Modo Interativo

Executa a interface baseada em menu.

```bash
python3 token_vault_secure.py
```

Exemplo:

```text
+------------------------------------------------------------+
|                 Token Vault Secure v0.6.0                  |
+------------------------------------------------------------+

Escolha uma opção:

1 - Adicionar alias
2 - Recuperar alias
3 - Editar alias
4 - Excluir alias
5 - Listar aliases
6 - Backup manual
7 - Trocar senha mestra
8 - Restaurar backup
99 - Sair
```

Este modo é indicado para uso cotidiano, dispensando a memorização de comandos.

---

### Modo CLI

Também é possível utilizar o sistema diretamente por linha de comando.

Listar registros:

```bash
python3 token_vault_secure.py list
```

Adicionar novo registro:

```bash
python3 token_vault_secure.py add github
```

Recuperar registro:

```bash
python3 token_vault_secure.py get github
```

Gerar backup:

```bash
python3 token_vault_secure.py backup
```

Alterar senha mestra:

```bash
python3 token_vault_secure.py changepass
```

---

## 🔧 Requisitos

* Python 3.12+
* GPG instalado e disponível no PATH

Dependências Python:

```bash
pip install cryptography
```

Dependências opcionais:

```bash
pip install argon2-cffi
pip install pyperclip
```

### Bibliotecas Utilizadas

* cryptography
* argon2-cffi (opcional)
* pyperclip (opcional)
* GnuPG (externo)

---

## 💾 Backups

O sistema realiza backups automáticos antes de operações críticas.

Também é possível criar backups manuais através do menu ou da CLI.

Os backups preservam a mesma proteção criptográfica do cofre principal.

---

## 🔐 Considerações de Segurança

O projeto utiliza primitivas criptográficas amplamente adotadas pela indústria:

* AES-GCM para criptografia autenticada
* Argon2 para derivação de chaves
* PBKDF2 como mecanismo de compatibilidade
* GPG para proteção do arquivo principal

Algumas medidas adicionais implementadas:

* Nonces aleatórios para cada operação de criptografia
* Salts independentes por registro
* Limpeza automática da área de transferência
* Sanitização de entradas do usuário
* Backups rotativos
* Separação entre proteção do cofre e proteção dos registros

---

## 🎯 Objetivos do Projeto

Este projeto foi criado principalmente para estudo e experimentação nas áreas de:

* Criptografia aplicada
* Gerenciamento seguro de segredos
* Aplicações CLI em Python
* Armazenamento seguro de credenciais
* Automação de rotinas administrativas
* Boas práticas de segurança em aplicações locais

---

## ⚠️ Aviso

Este projeto foi desenvolvido para fins educacionais e uso pessoal.

Embora utilize bibliotecas criptográficas consolidadas e práticas modernas de proteção de dados, ele não passou por auditoria profissional independente.

Não substitui soluções amplamente auditadas e consolidadas como KeePassXC, Bitwarden ou Password Store.

Utilize por sua própria conta e risco.
