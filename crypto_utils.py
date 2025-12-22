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


import random
def substitution_encrypt(text, key_alphabet):
    normal_alphabet = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ "
    text = text.upper()
    result = ""
    for char in text:
        if char in normal_alphabet:
            idx = normal_alphabet.index(char)
            result += key_alphabet[idx]
        else:
            result += char
    return result

def substitution_decrypt(text, key_alphabet):
    normal_alphabet = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ "
    result = ""
    for char in text:
        if char in key_alphabet:
            idx = key_alphabet.index(char)
            result += normal_alphabet[idx]
        else:
            result += char
    return result

# --- AFFINE CIPHER ---
def modInverse(a, m):
    for x in range(1, m):
        if (((a % m) * (x % m)) % m == 1):
            return x
    return -1

def affine_encrypt(text, a=5, b=8):
    # Formül: E(x) = (ax + b) mod 29
    result = ""
    alphabet = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"
    m = len(alphabet)
    for char in text.upper():
        if char in alphabet:
            x = alphabet.index(char)
            result += alphabet[(a * x + b) % m]
        else:
            result += char
    return result

def affine_decrypt(text, a=5, b=8):
    # Formül: D(x) = a^-1 * (x - b) mod 29
    result = ""
    alphabet = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"
    m = len(alphabet)
    a_inv = modInverse(a, m)
    if a_inv == -1: return "Hata: 'a' değerinin tersi yok!"
    
    for char in text.upper():
        if char in alphabet:
            y = alphabet.index(char)
            result += alphabet[(a_inv * (y - b)) % m]
        else:
            result += char
    return result

def shift_cipher_encrypt(text, n):
    # n değerini alfabe uzunluğuna göre mod alarak normalize edelim
    return caesar_encrypt(text, shift=n)

def shift_cipher_decrypt(text, n):
    return caesar_encrypt(text, shift=-n)