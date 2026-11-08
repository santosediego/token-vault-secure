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

## Uso pretendido

Este cofre **não** foi pensado para o dia a dia. Digitar a senha mestra e duas dicas, guardadas em lugares diferentes, é trabalhoso de propósito. A ideia é guardar aqui poucos segredos de alto valor (credenciais de administrador de servidor, códigos de recuperação de contas, chaves raramente usadas) e deixar o resto em um gerenciador de senhas convencional.

Em gerenciadores comuns, pedir a senha mestra de novo para abrir um item costuma ser apenas uma trava de interface: a chave de criptografia continua sendo a mesma. Aqui a separação é criptográfica: a chave de cada registro nasce das duas dicas e não é guardada em lugar nenhum.

---

# ✨ Características

* Interface em linha de comando (CLI)
* Menu interativo para uso simplificado
* Criptografia autenticada com AES-GCM
* Derivação de chaves utilizando Argon2 (com fallback para PBKDF2); o KDF e seus parâmetros ficam gravados em cada registro
* Armazenamento persistente protegido por GPG
* Local do cofre configurável (`--vault` ou `VAULT_PATH`)
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

O KDF (Argon2id ou PBKDF2) e os parâmetros usados ficam gravados no próprio registro. Por isso, um registro criado com Argon2id só abre com o `argon2-cffi` instalado; sem ele, o programa avisa qual pacote falta, em vez de dizer que as dicas estão erradas.

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

> ⚠️ O nome (descrição) de cada dica é guardado dentro do cofre, então quem abrir a primeira camada consegue lê-lo. Use um lembrete que só faça sentido para você (por exemplo, "dica do servidor A") e **não** o endereço do esconderijo ("gaveta do escritório"). Guarde cada dica em um lugar físico diferente.

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

Usar um cofre em outro local (a flag vale antes ou depois do comando):

```bash
python3 token_vault_secure.py --vault /caminho/meu-cofre.gpg list
python3 token_vault_secure.py get github --vault /caminho/meu-cofre.gpg
```

> ⚠️ Valores passados como argumento (`--secret` no `add`; `--dica1` e `--dica2` no `get`) ficam no histórico do shell e podem aparecer na lista de processos. Para segredos de verdade, prefira o modo interativo, que não deixa esses valores no histórico do shell.

---

# 📥 Instalação

Clone o repositório:

```bash
git clone https://github.com/santosediego/token-vault-secure.git
cd token-vault-secure
```

Crie um ambiente virtual (opcional, mas evita instalar pacotes no sistema) e instale as dependências:

```bash
python3 -m venv .venv
source .venv/bin/activate        # no Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

O `requirements.txt` traz `cryptography` (obrigatório), `argon2-cffi` e `pyperclip`.

> ⚠️ Mantenha o `argon2-cffi` instalado. Registros criados com Argon2id só abrem com ele. Sem o pacote, novos registros passam a usar PBKDF2.

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

Testado em Linux. No Windows deve funcionar com o Gpg4win no PATH, mas isso não foi testado, e as permissões `600`/`700` não têm efeito por lá.

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

# 📁 Local do cofre

Por padrão o cofre fica em `~/.vault/vault.gpg`. Para guardá-lo em outro lugar (outra pasta, um pendrive, uma pasta sincronizada):

```bash
python3 token_vault_secure.py --vault /caminho/meu-cofre.gpg
python3 token_vault_secure.py list --vault /media/pendrive/
```

A ordem de prioridade é: `--vault`, depois a variável `VAULT_PATH`, depois `VAULT_DIR` (que recebe o `vault.gpg` dentro) e, por fim, o padrão. Se o caminho for uma pasta, o arquivo `vault.gpg` é criado dentro dela.

* A pasta do cofre só recebe `chmod 700` se o programa a criar. Pastas que já existiam não são alteradas; o arquivo do cofre e os backups ficam com permissão `600`.
* Cofre novo: o programa mostra o caminho e pede a senha mestra duas vezes. Se aparecer "Cofre novo" e você esperava abrir um cofre existente, o caminho está errado.
* Os comandos `list`, `get`, `delete`, `backup` e `changepass` exigem um cofre existente: se ele não está no caminho, avisam e saem sem criar nada. Só `add` e `restore` aceitam um cofre inexistente.

---

# 💾 Backups

O sistema faz um backup automático antes das operações que alteram o cofre (adicionar, editar, excluir e trocar a senha mestra) e mantém os 5 mais recentes (`VAULT_BACKUP_KEEP`). Os backups ficam na mesma pasta do cofre, com o nome do arquivo seguido de `.bak.<data>` (automáticos) ou `.manualbak.<data>` (manuais), e podem ser restaurados pelo menu ou pelo comando `restore`.

**Copiar o backup para outro lugar é responsabilidade de quem usa.** O programa não envia nada para fora da máquina. Como o `vault.gpg` e seus backups são arquivos criptografados, podem ser levados para um NAS, pendrive ou nuvem sem exigir confiança no destino.

Lembre-se: perder o arquivo do cofre, ou qualquer uma das duas dicas de um registro, significa perder aquele segredo. Não existe recuperação.

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
* KDF e parâmetros gravados em cada registro (mudar as variáveis `VAULT_ARGON2_*` ou `VAULT_PBKDF2_ITERS` não quebra registros já criados)
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
* A senha recuperada é exibida no terminal e copiada para a área de transferência (que é limpa depois de 30 segundos).
* O nome das dicas fica dentro do cofre; não use nele o local onde a dica está guardada.
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
