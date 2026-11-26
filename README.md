# 🔒 Cofre USB — senha nos arquivos do pendrive

Script em **Python** que criptografa todos os arquivos de um pendrive com uma
**senha**. Sem a senha, quem abrir o pendrive vê apenas arquivos `.cofre` com
nomes aleatórios e conteúdo ilegível — nem os nomes nem as pastas originais
ficam visíveis.

Feito para **Windows 11 Home** (funciona também em Linux/macOS), sem precisar de
BitLocker.

---

## ✨ O que ele faz

- **Trancar:** criptografa todos os arquivos do pendrive.
- **Abrir:** descriptografa tudo de volta, com os nomes e pastas originais.
- Protege o **conteúdo**, o **nome** e a **pasta** de cada arquivo.
- Avisa quando a senha está errada ou o arquivo foi corrompido.

---

## 🧠 Como funciona (por dentro)

- A sua senha passa por **scrypt**, que a transforma em uma chave de 256 bits.
  O scrypt é lento de propósito, para dificultar ataques de força bruta.
- Cada arquivo é criptografado com **AES-256-GCM**, com uma chave própria.
- O nome e a pasta originais são guardados **dentro** do arquivo criptografado,
  também cifrados. No pendrive sobram só arquivos `.cofre` com nomes aleatórios.
- O GCM detecta senha errada e qualquer adulteração do arquivo.
- Antes de apagar o original, o script confere se a versão criptografada abre
  corretamente — assim você não perde arquivo por um erro no meio do caminho.

---

## 🚀 Como usar

### 1. Instale o Python
Baixe em [python.org](https://www.python.org/downloads/) e, na instalação,
marque **"Add Python to PATH"**.

### 2. Instale a biblioteca necessária
Abra o Prompt de Comando e rode:
```bash
pip install cryptography
```

### 3. Coloque o script no pendrive
Copie o arquivo **cofre.py** para a raiz do pendrive (ex.: `E:\`).

### 4. Use os comandos
No Prompt de Comando, entre na unidade do pendrive (ex.: digite `E:` e Enter) e
rode:

```bash
python cofre.py criar      # define a senha (só na primeira vez)
python cofre.py trancar    # criptografa todos os arquivos do pendrive
python cofre.py abrir      # descriptografa tudo de volta
```

Opcional — trancar/abrir outra pasta ou unidade:
```bash
python cofre.py trancar --pasta E:\
```

---

## ⚠️ Avisos importantes

- **Se esquecer a senha, não há como recuperar os arquivos.** Não existe
  "recuperar senha".
- Em pendrive (memória flash), um arquivo original apagado pode, às vezes, ser
  recuperado por ferramentas forenses. Para dados muito sensíveis, comece com o
  pendrive já trancado e só adicione arquivos novos, trancando em seguida.
- Para abrir em outro computador, ele também precisa de Python e da biblioteca
  `cryptography`.

---

## 🛠️ Tecnologias

- Python 3
- [cryptography](https://cryptography.io/) — AES-256-GCM, scrypt, HKDF

---

## 📄 Licença

Projeto de uso pessoal e educativo. Use por sua conta e risco.
