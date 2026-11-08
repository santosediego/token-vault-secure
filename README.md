# Token Vault Secure

[![Licença](https://img.shields.io/github/license/santosediego/token-vault-secure?style=for-the-badge)](https://github.com/santosediego/token-vault-secure/blob/main/LICENSE)

![Python](https://img.shields.io/badge/python_3.12+-%233776AB.svg?style=for-the-badge&logo=python&logoColor=white)
![GnuPG](https://img.shields.io/badge/gnupg-%230093DD.svg?style=for-the-badge&logo=gnuprivacyguard&logoColor=white)
![AES-GCM](https://img.shields.io/badge/aes--gcm-%23333333.svg?style=for-the-badge)
![Argon2](https://img.shields.io/badge/argon2-%23333333.svg?style=for-the-badge)

## Sobre o projeto

Cofre local para guardar credenciais, tokens, chaves de API e outras informações sensíveis, desenvolvido como estudo de criptografia aplicada e de aplicações CLI em Python.

Cada registro tem uma segunda camada de proteção, com chave derivada de duas informações independentes (as "dicas"). Conhecer a senha mestra não dá acesso aos segredos, e as dicas podem ficar guardadas em lugares separados.

O objetivo não é substituir soluções consolidadas, mas explorar a compartimentalização de segredos.

**Uso ideal:** senhas que exigem mais segurança, mas que não são requisitadas com frequência.

## Características

* Interface em linha de comando (CLI) e menu interativo
* Criptografia autenticada com AES-GCM
* Derivação de chaves com Argon2 (com PBKDF2 como alternativa); o KDF e seus parâmetros ficam gravados em cada registro
* Armazenamento persistente protegido por GPG
* Local do cofre configurável (`--vault` ou `VAULT_PATH`)
* Backups automáticos e manuais, com restauração
* Troca de senha mestra
* Limpeza automática da área de transferência após recuperação de segredos
* Suporte a campos adicionais (extras)

## Como funciona

### Fluxo simplificado

```text
Senha Mestra
      ↓
Vault protegido por GPG
      ↓
Registro selecionado
      ↓
Dica 1 + Dica 2
      ↓
Derivação de chave (Argon2/PBKDF2)
      ↓
AES-GCM
      ↓
Segredo recuperado
```

### Camada 1 — Cofre principal

Todo o conteúdo do cofre é armazenado em um arquivo criptografado com GPG. O acesso ao arquivo requer a senha mestra definida pelo usuário.

### Camada 2 — Proteção individual por registro

Cada segredo tem sua própria chave, derivada das duas dicas via Argon2id (ou PBKDF2 como alternativa). A chave não é guardada em lugar nenhum: mesmo com o cofre aberto, sem as dicas daquele registro não há como decifrá-lo.

O KDF e seus parâmetros ficam gravados no registro. Um registro criado com Argon2id só abre com o `argon2-cffi` instalado; sem ele, o programa avisa qual pacote falta.

### Estrutura dos dados

Cada registro contém:

* Alias identificador
* Metadados de recuperação
* Material criptográfico
* Segredo principal
* Campos adicionais opcionais (chaves TOTP, notas privadas, URLs de serviços, informações complementares de autenticação)

> **Dica:** por padrão, o sistema gera automaticamente as informações de recuperação da segunda camada. Recomenda-se usar essa geração automática sempre que possível, evitando valores previsíveis como datas, nomes ou palavras comuns.

> **Nota:** o nome de cada dica aparece quando o registro é aberto (segunda camada). Escolha um lembrete que só faça sentido para você, como "dica do servidor A", e evite indicar onde a dica está guardada. Guarde cada dica em um lugar físico diferente.

## Instalação

Clone o repositório:

```bash
git clone https://github.com/santosediego/token-vault-secure.git
cd token-vault-secure
```

Instale as dependências:

```bash
pip install -r requirements.txt
```

> **Nota:** em distribuições recentes (Debian, Ubuntu, Linux Mint), o `pip` pode recusar a instalação global com o erro `externally-managed-environment`. Nesse caso, use um ambiente virtual (venv):
>
> ```bash
> python3 -m venv .venv
> source .venv/bin/activate        # no Windows: .venv\Scripts\activate
> pip install -r requirements.txt
> ```
>
> Com o venv, ative-o antes de usar o programa ou chame o Python dele diretamente (`.venv/bin/python token_vault_secure.py`).

Verifique se o GPG está disponível:

```bash
gpg --version
```

### Requisitos

* Python 3.12+
* GPG instalado e disponível no PATH
* `cryptography`, `argon2-cffi` e `pyperclip` (todos no `requirements.txt`)

> **Atenção:** mantenha o `argon2-cffi` instalado. Registros criados com Argon2id só abrem com ele; sem o pacote, novos registros passam a usar PBKDF2.

Testado em Linux. No Windows deve funcionar com o Gpg4win no PATH, mas isso não foi testado, e as permissões `600`/`700` não têm efeito por lá.

## Como usar

### Modo interativo

Executa a interface baseada em menu, dispensando a memorização de comandos.

```bash
python3 token_vault_secure.py
```

Exemplo:

```text
+------------------------------------------------------------+
|                     Token Vault Secure                     |
+------------------------------------------------------------+
Cofre: /home/usuario/.vault/vault.gpg

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

### Modo CLI

Também é possível usar o sistema diretamente por linha de comando.

Listar registros:

```bash
python3 token_vault_secure.py list
```

Adicionar registro:

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

> **Atenção:** valores passados como argumento (`--secret` no `add`; `--dica1` e `--dica2` no `get`) ficam no histórico do shell e podem aparecer na lista de processos. Para segredos de verdade, prefira o modo interativo, que não deixa esses valores no histórico do shell.

### Local do cofre

Por padrão o cofre fica em `~/.vault/vault.gpg`. Para guardá-lo em outro lugar (outra pasta, um pendrive, uma pasta sincronizada), a flag `--vault` vale antes ou depois do comando:

```bash
python3 token_vault_secure.py --vault /caminho/meu-cofre.gpg list
python3 token_vault_secure.py get github --vault /media/pendrive/
```

A ordem de prioridade é: `--vault`, depois a variável `VAULT_PATH`, depois `VAULT_DIR` (que recebe o `vault.gpg` dentro) e, por fim, o padrão. Se o caminho for uma pasta, o arquivo `vault.gpg` é criado dentro dela.

Se aparecer "Cofre novo" e você esperava abrir um cofre existente, o caminho está errado.

### Backups

O sistema faz um backup automático antes das operações que alteram o cofre (adicionar, editar, excluir e trocar a senha mestra) e mantém os 5 mais recentes (`VAULT_BACKUP_KEEP`). Os backups ficam na mesma pasta do cofre, com o nome do arquivo seguido de `.bak.<data>` (automáticos) ou `.manualbak.<data>` (manuais), e podem ser restaurados pelo menu ou pelo comando `restore`.

Recomenda-se guardar uma cópia dos backups em um local seguro.

Perder o arquivo do cofre, ou qualquer uma das duas dicas de um registro, significa perder aquele segredo. Não existe recuperação.

## Segurança

### Medidas adotadas

* AES-GCM para criptografia autenticada
* Argon2 para derivação de chaves, com PBKDF2 como alternativa
* GPG para proteção do arquivo principal
* Nonces aleatórios para cada operação de criptografia
* Salts independentes por registro
* KDF e parâmetros gravados em cada registro (mudar as variáveis `VAULT_ARGON2_*` ou `VAULT_PBKDF2_ITERS` não quebra registros já criados)
* Limpeza automática da área de transferência
* Sanitização de entradas do usuário

### Modelo de ameaças

Este projeto busca oferecer proteção contra cenários como:

* Vazamento acidental do arquivo do cofre
* Acesso indevido ao armazenamento local
* Exposição da senha mestra sem conhecimento das informações de recuperação dos registros
* Comprometimento de um registro sem impacto direto sobre os demais

Não foi projetado para resistir a:

* Sistemas comprometidos por malware
* Keyloggers
* Captura de memória em tempo real
* Ataques físicos avançados ao equipamento

### Limitações conhecidas

* A limpeza de memória em Python não é garantida: strings são imutáveis e podem permanecer em memória por algum tempo após o uso.
* A sobrescrita de arquivos temporários é feita em modo melhor-esforço e não garante remoção física definitiva em SSDs ou sistemas com journaling.
* A segurança da segunda camada depende da qualidade das informações usadas para derivar as chaves.
* A senha recuperada é exibida no terminal e copiada para a área de transferência (que é limpa depois de 30 segundos).

## Solução de problemas

### GPG recusando a passphrase

O cofre usa `--pinentry-mode loopback` para fornecer a senha mestra diretamente ao GPG.

Caso receba erros relacionados a pinentry, habilite o suporte a loopback:

```bash
echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent
```

Após reiniciar o agente, tente executar novamente o programa.

> **Nota:** projeto educacional e de uso pessoal, sem auditoria independente de segurança. Para ambientes corporativos ou requisitos regulatórios, prefira soluções auditadas, como KeePassXC, Bitwarden ou Password Store.
