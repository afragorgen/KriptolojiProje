from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# --- CAESAR ---
def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isupper(): result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower(): result += chr((ord(char) + shift - 97) % 26 + 97)
        else: result += char
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

# --- VIGENERE ---
def vigenere_encrypt(text, key):
    result = ""; key = key.upper(); k_idx = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[k_idx % len(key)]) - 65
            if char.isupper(): result += chr((ord(char) + shift - 65) % 26 + 65)
            else: result += chr((ord(char) + shift - 97) % 26 + 97)
            k_idx += 1
        else: result += char
    return result

def vigenere_decrypt(text, key):
    result = ""; key = key.upper(); k_idx = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[k_idx % len(key)]) - 65
            if char.isupper(): result += chr((ord(char) - shift - 65) % 26 + 65)
            else: result += chr((ord(char) - shift - 97) % 26 + 97)
            k_idx += 1
        else: result += char
    return result

# --- AES ---
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(combined_data, key):
    iv = combined_data[:16]; ct = combined_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()