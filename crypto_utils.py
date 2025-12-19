from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# --- CAESAR (SEZAR) ŞİFRELEME (Klasik) ---
def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char # Harf dışı karakterleri olduğu gibi bırak
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

# --- AES ŞİFRELEME (Simetrik Modern) ---
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(combined_data, key):
    iv = combined_data[:16]
    ct = combined_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# --- RSA ANAHTAR ÜRETİMİ (Asimetrik Modern) ---
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def vigenere_encrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            # Kaydırma miktarını anahtarın o anki harfinden al (A=0, B=1...)
            shift = ord(key[key_index % len(key)]) - 65
            if char.isupper():
                result += chr((ord(char) + shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) + shift - 97) % 26 + 97)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            # Şifre çözmek için kaydırmayı çıkarıyoruz
            shift = ord(key[key_index % len(key)]) - 65
            if char.isupper():
                result += chr((ord(char) - shift - 65) % 26 + 65)
            else:
                result += chr((ord(char) - shift - 97) % 26 + 97)
            key_index += 1
        else:
            result += char
    return result