import numpy as np
from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# --- ALFABE TANIMI ---
ALPHABET = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"
M = len(ALPHABET)

# MODERN ALGORİTMALAR (AES, RSA, BLOWFISH)

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(combined_data, key):
    iv = combined_data[:16]
    ct = combined_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

def blowfish_encrypt(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), Blowfish.block_size))
    return cipher.iv + ct_bytes

def blowfish_decrypt(combined_data, key):
    iv = combined_data[:8]
    ct = combined_data[8:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), Blowfish.block_size).decode()

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

# KLASİK & MATEMATİKSEL ALGORİTMALAR

def hill_encrypt(text):
    K = np.array([[3, 3], [2, 5]])
    text = "".join([c for c in text.upper() if c in ALPHABET])
    if len(text) % 2 != 0: text += "X"
    result = ""
    for i in range(0, len(text), 2):
        P = np.array([ALPHABET.index(text[i]), ALPHABET.index(text[i+1])])
        C = np.dot(K, P) % M
        result += ALPHABET[C[0]] + ALPHABET[C[1]]
    return result

def hill_decrypt(text):
    K_inv = np.array([[15, 20], [23, 9]]) 
    result = ""
    for i in range(0, len(text), 2):
        C = np.array([ALPHABET.index(text[i]), ALPHABET.index(text[i+1])])
        P = np.dot(K_inv, C) % M
        result += ALPHABET[P[0]] + ALPHABET[P[1]]
    return result

def caesar_encrypt(text, shift=3):
    result = ""
    for char in text.upper():
        if char in ALPHABET:
            idx = (ALPHABET.index(char) + shift) % M
            result += ALPHABET[idx]
        else: result += char
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    result = ""; key = key.upper(); k_idx = 0
    for char in text.upper():
        if char in ALPHABET:
            shift = ALPHABET.index(key[k_idx % len(key)])
            result += ALPHABET[(ALPHABET.index(char) + shift) % M]
            k_idx += 1
        else: result += char
    return result

def vigenere_decrypt(text, key):
    result = ""; key = key.upper(); k_idx = 0
    for char in text.upper():
        if char in ALPHABET:
            shift = ALPHABET.index(key[k_idx % len(key)])
            result += ALPHABET[(ALPHABET.index(char) - shift) % M]
            k_idx += 1
        else: result += char
    return result

def affine_encrypt(text, a=5, b=8):
    result = ""
    for char in text.upper():
        if char in ALPHABET:
            result += ALPHABET[(a * ALPHABET.index(char) + b) % M]
        else: result += char
    return result

def affine_decrypt(text, a=5, b=8):
    def modInverse(a, m):
        for x in range(1, m):
            if (((a % m) * (x % m)) % m == 1): return x
        return -1
    a_inv = modInverse(a, M)
    result = ""
    for char in text.upper():
        if char in ALPHABET:
            result += ALPHABET[(a_inv * (ALPHABET.index(char) - b)) % M]
        else: result += char
    return result

def substitution_encrypt(text, key_alphabet):
    result = ""
    for char in text.upper():
        if char in ALPHABET: result += key_alphabet[ALPHABET.index(char)]
        else: result += char
    return result

def substitution_decrypt(text, key_alphabet):
    result = ""
    for char in text.upper():
        if char in key_alphabet: result += ALPHABET[key_alphabet.index(char)]
        else: result += char
    return result

# --- RAIL FENCE CIPHER ---
def rail_fence_encrypt(text, rails=2):
    # Çitleri oluştur
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1  # 1: aşağı, -1: yukarı

    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
            
    return "".join(["".join(r) for r in fence])

def rail_fence_decrypt(cipher, rails=2):
    # Boş çit yapısını kur
    fence = [['\n' for _ in range(len(cipher))] for _ in range(rails)]
    rail = 0
    direction = 1

    # Harflerin nereye geleceğini işaretle
    for i in range(len(cipher)):
        fence[rail][i] = '*'
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1

    # İşaretli yerlere şifreli metnin harflerini yerleştir
    index = 0
    for r in range(rails):
        for c in range(len(cipher)):
            if fence[r][c] == '*' and index < len(cipher):
                fence[r][c] = cipher[index]
                index += 1

    # Zikzak çizerek oku
    result = []
    rail = 0
    direction = 1
    for i in range(len(cipher)):
        result.append(fence[rail][i])
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
            
    return "".join(result)