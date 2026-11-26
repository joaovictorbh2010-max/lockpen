#!/usr/bin/env python3
"""
cofre.py - tranca (criptografa) e abre os arquivos de um pendrive com senha.

Coloque este arquivo na raiz do pendrive e rode, no Prompt de Comando:

    python cofre.py criar      -> define a senha (so na primeira vez)
    python cofre.py trancar    -> criptografa todos os arquivos do pendrive
    python cofre.py abrir      -> descriptografa tudo de volta

Opcional: --pasta E:\\   (para trancar/abrir outra pasta ou unidade)

Requer:  pip install cryptography

Como funciona:
  - Sua senha vira uma chave de 256 bits com scrypt (lento de proposito,
    para dificultar ataques de forca bruta).
  - Cada arquivo e criptografado com AES-256-GCM, com chave propria.
  - O nome e a pasta original tambem ficam criptografados; no pendrive
    sobram so arquivos com nomes aleatorios terminados em .cofre.
  - GCM detecta senha errada e arquivos adulterados/corrompidos.

ATENCAO: se esquecer a senha, NAO ha como recuperar os arquivos.
"""
import argparse
import base64
import getpass
import json
import os
import secrets
import struct
import sys
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    sys.exit("Falta a biblioteca 'cryptography'. Instale com:  pip install cryptography")

MAGIC = b"COFRE1\0\0"          # 8 bytes que identificam o formato
SALT_LEN = 16
HEADER_LEN = len(MAGIC) + SALT_LEN
CHUNK = 1024 * 1024            # criptografa em blocos de 1 MB (aguenta arquivos grandes)
CONFIG = "cofre.json"
EXT = ".cofre"
SCRYPT_N = 2 ** 17             # ~128 MB de RAM, ~0,5 s por tentativa de senha
IGNORAR_PASTAS = {"System Volume Information", "$RECYCLE.BIN"}


# ---------------------------------------------------------------- chaves

def derivar_mestra(senha: str, salt: bytes, n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(senha.encode("utf-8"))


def subchave(mestra: bytes, salt: bytes, uso: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=uso).derive(mestra)


def nonce(i: int) -> bytes:
    # cada arquivo tem chave unica, entao um contador como nonce e seguro
    return struct.pack(">IQ", 0, i)


def aad(header: bytes, i: int, final: int) -> bytes:
    # amarra cada bloco a sua posicao e marca o ultimo:
    # impede reordenar, remover ou cortar blocos sem ser detectado
    return header + struct.pack(">QB", i, final)


# ---------------------------------------------------------------- arquivos

def criptografar(origem: Path, destino: Path, mestra: bytes, relpath: str) -> None:
    salt = secrets.token_bytes(SALT_LEN)
    header = MAGIC + salt
    aes = AESGCM(subchave(mestra, salt, b"cofre-arquivo"))
    i = 0
    with open(origem, "rb") as fin, open(destino, "wb") as fout:
        fout.write(header)

        def escreve(dados: bytes, final: int) -> None:
            nonlocal i
            ct = aes.encrypt(nonce(i), dados, aad(header, i, final))
            fout.write(struct.pack(">I", len(ct)))
            fout.write(ct)
            i += 1

        escreve(relpath.encode("utf-8"), 0)          # bloco 0 = nome/pasta original
        atual = fin.read(CHUNK)
        while True:
            prox = fin.read(CHUNK)
            escreve(atual, 0 if prox else 1)
            if not prox:
                break
            atual = prox
        fout.flush()
        os.fsync(fout.fileno())


def descriptografar(caminho: Path, mestra: bytes, saida_base: Path | None) -> str:
    """Descriptografa `caminho`. Se saida_base for None, so verifica.
    Retorna o caminho relativo original."""
    tmp = None
    fout = None
    try:
        with open(caminho, "rb") as f:
            header = f.read(HEADER_LEN)
            if len(header) != HEADER_LEN or not header.startswith(MAGIC):
                raise ValueError("nao e um arquivo do cofre")
            aes = AESGCM(subchave(mestra, header[len(MAGIC):], b"cofre-arquivo"))
            i, relpath = 0, None
            while True:
                tam_b = f.read(4)
                if len(tam_b) < 4:
                    raise ValueError("arquivo cortado/corrompido")
                (tam,) = struct.unpack(">I", tam_b)
                ct = f.read(tam)
                if len(ct) != tam:
                    raise ValueError("arquivo cortado/corrompido")
                final = 0
                try:
                    dados = aes.decrypt(nonce(i), ct, aad(header, i, 0))
                except InvalidTag:
                    if i == 0:
                        raise ValueError("senha errada ou arquivo adulterado")
                    try:
                        dados = aes.decrypt(nonce(i), ct, aad(header, i, 1))
                        final = 1
                    except InvalidTag:
                        raise ValueError("arquivo adulterado/corrompido")

                if i == 0:
                    relpath = dados.decode("utf-8")
                    if saida_base is not None:
                        alvo = caminho_seguro(saida_base, relpath)
                        alvo.parent.mkdir(parents=True, exist_ok=True)
                        tmp = alvo.with_name(alvo.name + ".restaurando")
                        fout = open(tmp, "wb")
                elif fout is not None:
                    fout.write(dados)
                i += 1
                if final:
                    if f.read(1):
                        raise ValueError("dados extras apos o fim")
                    break
        if fout is not None:
            fout.close()
            fout = None
            alvo = nome_livre(caminho_seguro(saida_base, relpath))
            os.replace(tmp, alvo)
            tmp = None
        return relpath
    finally:
        if fout is not None:
            fout.close()
        if tmp is not None and tmp.exists():
            tmp.unlink()


def caminho_seguro(base: Path, relpath: str) -> Path:
    alvo = (base / relpath).resolve()
    if base.resolve() not in alvo.parents:
        raise ValueError(f"caminho suspeito: {relpath}")
    return alvo


def nome_livre(alvo: Path) -> Path:
    if not alvo.exists():
        return alvo
    n = 1
    while True:
        cand = alvo.with_name(f"{alvo.stem} (restaurado {n}){alvo.suffix}")
        if not cand.exists():
            return cand
        n += 1


# ---------------------------------------------------------------- config / senha

def proprios_arquivos() -> set[Path]:
    s = {Path(__file__).resolve()}
    if getattr(sys, "frozen", False):        # se virar .exe com PyInstaller
        s.add(Path(sys.executable).resolve())
    return s


def carregar_mestra(pasta: Path) -> bytes:
    cfg_path = pasta / CONFIG
    if not cfg_path.exists():
        sys.exit(f"Nenhum cofre aqui. Rode primeiro:  python {Path(__file__).name} criar")
    cfg = json.loads(cfg_path.read_text("utf-8"))
    salt = base64.b64decode(cfg["salt"])
    verif = base64.b64decode(cfg["verificador"])
    senha = getpass.getpass("Senha: ")
    print("Verificando senha...")
    mestra = derivar_mestra(senha, salt, cfg["n"])
    try:
        AESGCM(subchave(mestra, salt, b"cofre-verifica")).decrypt(nonce(0), verif, None)
    except InvalidTag:
        sys.exit("Senha errada.")
    return mestra


def cmd_criar(pasta: Path) -> None:
    cfg_path = pasta / CONFIG
    if cfg_path.exists():
        sys.exit("Ja existe um cofre aqui (cofre.json). Nada foi alterado.")
    senha = getpass.getpass("Nova senha (minimo 8 caracteres): ")
    if len(senha) < 8:
        sys.exit("Senha muito curta.")
    if getpass.getpass("Repita a senha: ") != senha:
        sys.exit("As senhas nao conferem.")
    salt = secrets.token_bytes(SALT_LEN)
    mestra = derivar_mestra(senha, salt, SCRYPT_N)
    verif = AESGCM(subchave(mestra, salt, b"cofre-verifica")).encrypt(nonce(0), b"cofre-ok", None)
    cfg = {"versao": 1, "n": SCRYPT_N,
           "salt": base64.b64encode(salt).decode(),
           "verificador": base64.b64encode(verif).decode()}
    cfg_path.write_text(json.dumps(cfg, indent=2), "utf-8")
    print("Cofre criado. Agora rode:  python cofre.py trancar")
    print("Lembre: sem a senha, nao ha como recuperar os arquivos.")


def listar(pasta: Path, quer_cofre: bool) -> list[Path]:
    pular = proprios_arquivos() | {(pasta / CONFIG).resolve()}
    achados = []
    for raiz, dirs, arqs in os.walk(pasta):
        dirs[:] = [d for d in dirs if d not in IGNORAR_PASTAS]
        for nome in arqs:
            p = Path(raiz) / nome
            if p.resolve() in pular or nome.endswith((".tmp", ".restaurando")):
                continue
            if nome.endswith(EXT) == quer_cofre:
                achados.append(p)
    return achados


def remover_pastas_vazias(pasta: Path) -> None:
    for raiz, dirs, arqs in os.walk(pasta, topdown=False):
        r = Path(raiz)
        if r != pasta and r.name not in IGNORAR_PASTAS and not any(r.iterdir()):
            r.rmdir()


def cmd_trancar(pasta: Path) -> None:
    arquivos = listar(pasta, quer_cofre=False)
    if not arquivos:
        print("Nada para trancar.")
        return
    mestra = carregar_mestra(pasta)
    ok = falhas = 0
    for arq in arquivos:
        rel = arq.relative_to(pasta).as_posix()
        destino = pasta / (secrets.token_hex(8) + EXT)
        tmp = destino.with_suffix(".tmp")
        try:
            criptografar(arq, tmp, mestra, rel)
            descriptografar(tmp, mestra, None)     # confere antes de apagar o original
            os.replace(tmp, destino)
            arq.unlink()
            ok += 1
            print(f"  trancado: {rel}")
        except Exception as e:
            falhas += 1
            if tmp.exists():
                tmp.unlink()
            print(f"  FALHOU:   {rel} ({e}) - original mantido")
    remover_pastas_vazias(pasta)
    print(f"\n{ok} arquivo(s) trancado(s), {falhas} falha(s).")


def cmd_abrir(pasta: Path) -> None:
    arquivos = listar(pasta, quer_cofre=True)
    if not arquivos:
        print("Nada para abrir.")
        return
    mestra = carregar_mestra(pasta)
    ok = falhas = 0
    for arq in arquivos:
        try:
            rel = descriptografar(arq, mestra, pasta)
            arq.unlink()
            ok += 1
            print(f"  aberto: {rel}")
        except Exception as e:
            falhas += 1
            print(f"  FALHOU: {arq.name} ({e}) - arquivo criptografado mantido")
    print(f"\n{ok} arquivo(s) aberto(s), {falhas} falha(s).")


def main() -> None:
    ap = argparse.ArgumentParser(description="Cofre com senha para pendrive.")
    ap.add_argument("comando", choices=["criar", "trancar", "abrir"])
    ap.add_argument("--pasta", help="pasta/unidade alvo (padrao: onde o script esta)")
    a = ap.parse_args()
    pasta = Path(a.pasta).resolve() if a.pasta else Path(__file__).resolve().parent
    {"criar": cmd_criar, "trancar": cmd_trancar, "abrir": cmd_abrir}[a.comando](pasta)


if __name__ == "__main__":
    main()
