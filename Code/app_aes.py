# app_aes.py
# Petite application de chiffrement / déchiffrement de fichiers avec AES

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes  # pas obligatoire, mais utile si tu veux
import hashlib
import os
from pathlib import Path


# ---------- AES bas niveau ----------

def aes_encrypt(message: bytes, key: bytes, mode_name: str = "CBC"):
    """
    Chiffre un message (bytes) avec AES + padding PKCS#7.
    Retourne (ciphertext, iv, mode_used)
    """
    mode_name = mode_name.upper()

    if mode_name == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        iv = None
    elif mode_name == "CBC":
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
    elif mode_name == "OFB":
        cipher = AES.new(key, AES.MODE_OFB)
        iv = cipher.iv
    else:
        raise ValueError("Mode non supporté (utiliser: ECB, CBC, OFB)")

    padded = pad(message, AES.block_size)
    c = cipher.encrypt(padded)
    return c, iv, mode_name


def aes_decrypt(ciphertext: bytes, key: bytes, mode_name: str, iv: bytes = None) -> bytes:
    """
    Déchiffre un message AES selon le mode choisi.
    """
    mode_name = mode_name.upper()

    if mode_name == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
    elif mode_name == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif mode_name == "OFB":
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    else:
        raise ValueError("Mode non supporté (utiliser: ECB, CBC, OFB)")

    padded = cipher.decrypt(ciphertext)
    message = unpad(padded, AES.block_size)
    return message


# ---------- AES sur fichiers ----------

def aes_encrypt_file(input_path: str, output_path: str, key: bytes, mode_name: str = "CBC"):
    """
    Chiffre un fichier binaire (texte, image, audio, etc.) avec AES.
    """
    mode_name = mode_name.upper()

    with open(input_path, "rb") as f:
        data = f.read()

    c, iv, mode_used = aes_encrypt(data, key, mode_name)

    # On stocke : mode | iv_length | iv | ciphertext
    with open(output_path, "wb") as f:
        f.write(mode_used.encode("ascii") + b"|")
        iv_bytes = iv if iv is not None else b""
        f.write(len(iv_bytes).to_bytes(1, "big"))
        f.write(iv_bytes)
        f.write(c)


def aes_decrypt_file(input_path: str, output_path: str, key: bytes):
    """
    Déchiffre un fichier binaire chiffré par aes_encrypt_file.
    """
    with open(input_path, "rb") as f:
        header = b""
        while True:
            ch = f.read(1)
            if ch == b"|":
                break
            header += ch
        mode_name = header.decode("ascii")
        iv_len = int.from_bytes(f.read(1), "big")
        iv = f.read(iv_len) if iv_len > 0 else None
        c = f.read()

    data = aes_decrypt(c, key, mode_name, iv)
    with open(output_path, "wb") as f:
        f.write(data)


# ---------- dérivation de clé depuis un mot de passe ----------

def make_key_from_password(password: str) -> bytes:
    """
    Dérive une clé AES 256 bits à partir d'un mot de passe (SHA-256).
    """
    return hashlib.sha256(password.encode()).digest()


def encrypt_file_with_password(input_path: str, output_path: str, password: str, mode_name: str = "CBC"):
    key = make_key_from_password(password)
    aes_encrypt_file(input_path, output_path, key, mode_name)


def decrypt_file_with_password(input_path: str, output_path: str, password: str):
    key = make_key_from_password(password)
    aes_decrypt_file(input_path, output_path, key)


# ---------- Application ligne de commande ----------

def app_crypto():
    print("=== Application de chiffrement/déchiffrement AES ===")
    
    action = input("Tapez E pour chiffrer, D pour déchiffrer : ").strip().upper()
    if action not in ("E", "D"):
        print("Action invalide.")
        return
    
    in_file = input("Chemin du fichier à traiter : ").strip()
    if not os.path.isfile(in_file):
        print("Fichier introuvable :", in_file)
        return
    
    password = input("Mot de passe (clé de chiffrement) : ")
    
    if action == "E":
        mode = input("Mode AES (ECB, CBC, OFB) [CBC par défaut] : ").strip().upper()
        if mode == "":
            mode = "CBC"
        
        base = Path(in_file)
        out_file = str(base.with_suffix(base.suffix + ".enc"))
        
        encrypt_file_with_password(in_file, out_file, password, mode)
        print(f"Fichier chiffré en {mode} -> {out_file}")
    
    else:  # D
        base = Path(in_file)
        suggestion = ""
        if base.suffix == ".enc":
            suggestion = str(base.with_suffix(""))
        
        out_file = input(f"Chemin de sortie (vide pour '{suggestion or (in_file + '.dec')}') : ").strip()
        if out_file == "":
            out_file = suggestion or (in_file + ".dec")
        
        decrypt_file_with_password(in_file, out_file, password)
        print(f"Fichier déchiffré -> {out_file}")


if __name__ == "__main__":
    app_crypto()
