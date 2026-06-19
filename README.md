# Token Vault Secure 🔐

Cofre local para armazenamento seguro de credenciais, tokens, chaves de API e outras informações sensíveis.

O projeto foi desenvolvido como estudo de criptografia aplicada, gerenciamento seguro de segredos e desenvolvimento de aplicações de linha de comando em Python.

Diferente de muitos gerenciadores de senhas tradicionais, cada registro pode possuir uma camada adicional de proteção criptográfica baseada em informações independentes de recuperação.

O objetivo não é substituir soluções consolidadas do mercado, mas explorar um modelo de compartimentalização de segredos onde o acesso ao cofre não implica necessariamente acesso imediato a todas as informações armazenadas.

---

# 🎯 Ideia Principal

A proposta do projeto é permitir que o usuário compartimentalize seus segredos.

Mesmo que a senha mestra do cofre seja conhecida, cada registro exige informações adicionais independentes para sua recuperação.

Essas informações podem ser armazenadas separadamente, reduzindo a dependência de um único fator de acesso e dificultando a exposição completa do conteúdo do cofre.

---

# ✨ Características

* Interface em linha de comando (CLI)
* Menu interativo para uso simplificado
* Criptografia autenticada com AES-GCM
* Derivação de chaves utilizando Argon2 (com fallback para PBKDF2)
* Armazenamento persistente protegido por GPG
* Backups automáticos e manuais
* Troca de senha mestra
* Limpeza automática da área de transferência após recuperação de segredos
* Suporte a campos adicionais (extras)
* Recuperação e restauração de backups
* Geração automática de informações auxiliares de recuperação

---

# 🏗️ Arquitetura de Proteção

O sistema utiliza múltiplas camadas de proteção para reduzir pontos únicos de falha.

## Fluxo Simplificado

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

Cada registro exige suas próprias informações de recuperação para derivação da chave utilizada na descriptografia.

## Camada 1 — Cofre Principal

Todo o conteúdo do cofre é armazenado em um arquivo criptografado utilizando GPG.

O acesso ao arquivo requer a senha mestra definida pelo usuário.

## Camada 2 — Proteção Individual por Registro

Cada segredo armazenado possui sua própria chave criptográfica derivada a partir de duas informações independentes de recuperação.

Essas informações são utilizadas para gerar uma chave exclusiva através de Argon2 (ou PBKDF2 como fallback), protegendo individualmente cada registro.

Mesmo com acesso ao arquivo do cofre, ainda é necessário conhecer as informações utilizadas para derivação da chave daquele registro específico.

---

# 📦 Estrutura dos Dados

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

> 💡 Por padrão, o sistema gera automaticamente as informações de recuperação utilizadas pela segunda camada de proteção. Recomenda-se utilizar essa geração automática sempre que possível, evitando valores previsíveis como datas, nomes ou palavras comuns.

---

# 🖥️ Modos de Utilização

## Modo Interativo

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

## Modo CLI

Também é possível utilizar o sistema diretamente por linha de comando.

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

---

# 📥 Instalação

Clone o repositório:

```bash
git clone https://github.com/santosediego/token-vault-secure.git
cd token-vault-secure
```

Instale as dependências obrigatórias:

```bash
pip install cryptography
```

Dependências opcionais:

```bash
pip install argon2-cffi
pip install pyperclip
```

Verifique se o GPG está disponível:

```bash
gpg --version
```

---

# 🔧 Requisitos

* Python 3.12+
* GPG instalado e disponível no PATH

## Bibliotecas Utilizadas

* cryptography
* argon2-cffi (opcional)
* pyperclip (opcional)
* GnuPG (externo)

---

# 🔧 Solução de Problemas

## GPG recusando a passphrase

O cofre utiliza `--pinentry-mode loopback` para fornecer a senha mestra diretamente ao GPG.

Caso receba erros relacionados a pinentry, habilite o suporte a loopback:

```bash
echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent
```

Após reiniciar o agente, tente executar novamente o programa.

---

# 💾 Backups

O sistema realiza backups automáticos antes de operações críticas.

Também é possível criar backups manuais através do menu ou da CLI.

Os backups preservam a mesma proteção criptográfica aplicada ao cofre principal.

---

# 🔐 Considerações de Segurança

O projeto utiliza primitivas criptográficas amplamente adotadas pela indústria:

* AES-GCM para criptografia autenticada
* Argon2 para derivação de chaves
* PBKDF2 como mecanismo de compatibilidade
* GPG para proteção do arquivo principal

Medidas adicionais implementadas:

* Nonces aleatórios para cada operação de criptografia
* Salts independentes por registro
* Limpeza automática da área de transferência
* Sanitização de entradas do usuário
* Backups rotativos
* Separação entre proteção do cofre e proteção dos registros

## Modelo de Ameaças

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

---

# 🚧 Limitações Conhecidas

Nenhuma implementação é perfeita, e é importante deixar claros os limites desta solução.

* A limpeza de memória em Python não é garantida.
* Strings em Python são imutáveis e podem permanecer em memória por algum tempo após o uso.
* A sobrescrita de arquivos temporários é realizada em modo melhor-esforço e não garante remoção física definitiva em SSDs ou sistemas com journaling.
* A segurança da segunda camada depende da qualidade das informações utilizadas para derivação das chaves.
* O projeto não passou por auditoria independente de segurança.

---

# 🎯 Objetivos do Projeto

Este projeto foi criado principalmente para estudo e experimentação nas áreas de:

* Criptografia aplicada
* Gerenciamento seguro de segredos
* Aplicações CLI em Python
* Armazenamento seguro de credenciais
* Automação de rotinas administrativas
* Boas práticas de segurança em aplicações locais

---

# ⚠️ Aviso

Este projeto foi desenvolvido para fins educacionais, experimentação técnica e uso pessoal.

Embora utilize bibliotecas criptográficas amplamente adotadas e práticas modernas de proteção de dados, ele não passou por auditoria profissional independente.

Para ambientes corporativos, requisitos regulatórios ou armazenamento de informações críticas, recomenda-se a utilização de soluções amplamente auditadas e consolidadas, como KeePassXC, Bitwarden ou Password Store.

Utilize por sua própria conta e risco.
