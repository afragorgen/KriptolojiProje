import os
import sys
import numpy as np
import math
from flask import Flask, render_template, request
from Crypto.Cipher import DES, PKCS1_OAEP, AES, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# ==========================================
# 1. S-DES ALGORİTMASI (ENTEGRE)
# ==========================================
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
P4 = (2, 4, 3, 1)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

def permute(bits, table): return [bits[i - 1] for i in table]
def shift(bits, n): return bits[n:] + bits[:n]

def sdes_key_gen(key_10bit):
    p10_key = permute(key_10bit, P10)
    l, r = p10_key[:5], p10_key[5:]
    l1, r1 = shift(l, 1), shift(r, 1)
    k1 = permute(l1 + r1, P8)
    l2, r2 = shift(l1, 2), shift(r1, 2)
    k2 = permute(l2 + r2, P8)
    return k1, k2

def f_k(bits, key):
    l, r = bits[:4], bits[4:]
    ep = permute(r, EP)
    x = [b ^ k for b, k in zip(ep, key)]
    l_x, r_x = x[:4], x[4:]
    v0 = format(S0[l_x[0]*2+l_x[3]][l_x[1]*2+l_x[2]], '02b')
    v1 = format(S1[r_x[0]*2+r_x[3]][r_x[1]*2+r_x[2]], '02b')
    p4 = permute([int(b) for b in v0 + v1], P4)
    return [b1 ^ b2 for b1, b2 in zip(l, p4)] + r

def sdes_encrypt_text(text):
    key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]
    k1, k2 = sdes_key_gen(key)
    res = []
    for c in text:
        b = [int(i) for i in format(ord(c), '08b')]
        bits = permute(b, IP)
        bits = f_k(bits, k1)
        bits = bits[4:] + bits[:4]
        bits = f_k(bits, k2)
        res.append(format(int("".join(map(str, permute(bits, IP_INV))), 2), '02X'))
    return "-".join(res)

# ==========================================
# 2. FLASK VE MODÜL AYARLARI
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

try:
    from crypto_utils import *
    print(">>> [BAŞARILI] crypto_utils yüklendi.")
except ImportError as e:
    print(f">>> [HATA] crypto_utils.py bulunamadı: {e}")

app = Flask(__name__)

# --- SABİT ANAHTARLAR ---
AES_KEY = b'16byte_uzun_key!'
BLOWFISH_KEY = b'blowfish_key_64'
DES_KEY = b'8byt_key'
SUB_KEY = "QWERTYUIOPĞÜASDFGHJKLŞİZXCVBNM "
SHIFT_N = 5
TRANS_KEY = "KRIPTO" # Columnar için

# RSA Hazırlığı
PRIVATE_KEY_PEM, PUBLIC_KEY_PEM = generate_rsa_keys()
SERVER_PRIVATE_KEY = RSA.import_key(PRIVATE_KEY_PEM)
SERVER_PUBLIC_KEY = RSA.import_key(PUBLIC_KEY_PEM)

@app.route('/')
def index():
    return render_template('index.html')

# ==========================================
# 📤 ŞİFRELEME ROTASI
# ==========================================
@app.route('/send', methods=['POST'])
def send():
    msg = request.form.get('message', '').upper()
    algo = request.form.get('algo', 'AES')
    try:
        if algo == "AES":
            enc_b = aes_encrypt(msg, AES_KEY); encrypted = enc_b.hex()
            decrypted = aes_decrypt(enc_b, AES_KEY)
        elif algo == "BLOWFISH":
            enc_b = blowfish_encrypt(msg, BLOWFISH_KEY); encrypted = enc_b.hex()
            decrypted = blowfish_decrypt(enc_b, BLOWFISH_KEY)
        elif algo == "RSA":
            c = PKCS1_OAEP.new(SERVER_PUBLIC_KEY); enc_b = c.encrypt(msg.encode())
            encrypted = enc_b.hex(); decrypted = PKCS1_OAEP.new(SERVER_PRIVATE_KEY).decrypt(enc_b).decode()
        elif algo == "HILL":
            encrypted = hill_encrypt(msg); decrypted = hill_decrypt(encrypted)
        elif algo == "COLUMNAR":
            encrypted = columnar_encrypt(msg, TRANS_KEY); decrypted = columnar_decrypt(encrypted, TRANS_KEY)
        elif algo == "RAILFENCE":
            encrypted = rail_fence_encrypt(msg, 3); decrypted = rail_fence_decrypt(encrypted, 3)
        elif algo == "SHIFT":
            encrypted = caesar_encrypt(msg, SHIFT_N); decrypted = caesar_decrypt(encrypted, SHIFT_N)
        elif algo == "CAESAR":
            encrypted = caesar_encrypt(msg, 3); decrypted = caesar_decrypt(encrypted, 3)
        elif algo == "AFFINE":
            encrypted = affine_encrypt(msg, 5, 8); decrypted = affine_decrypt(encrypted, 5, 8)
        elif algo == "SUBSTITUTION":
            encrypted = substitution_encrypt(msg, SUB_KEY); decrypted = substitution_decrypt(encrypted, SUB_KEY)
        elif algo == "VIGENERE":
            encrypted = vigenere_encrypt(msg, "KRIPTO"); decrypted = vigenere_decrypt(encrypted, "KRIPTO")
        elif algo == "DES":
            c = DES.new(DES_KEY, DES.MODE_ECB); enc_b = c.encrypt(pad(msg.encode(), DES.block_size))
            encrypted = enc_b.hex(); decrypted = unpad(c.decrypt(enc_b), DES.block_size).decode()
        elif algo == "SDES":
            encrypted = sdes_encrypt_text(msg); decrypted = "[Eğitim Modu]"
        elif algo == "ROUTE":
             encrypted = route_encrypt(msg, 4)
             decrypted = "[Çözme: Manuel Rota Takibi]"
      
 
        
        res = {"algo": algo, "encrypted": encrypted, "decrypted": decrypted, "mode": "Şifreleme"}
    except Exception as e:
        res = {"algo": algo, "error": f"Hata: {str(e)}"}
    return render_template('index.html', result=res)

# ==========================================
# 🔓 ŞİFRE ÇÖZME ROTASI
# ==========================================
@app.route('/decrypt', methods=['POST'])
def decrypt_direct():
    enc_text = request.form.get('encrypted_message', '').strip()
    algo = request.form.get('algo', 'AES')
    try:
        if algo == "AES": decrypted = aes_decrypt(bytes.fromhex(enc_text), AES_KEY)
        elif algo == "BLOWFISH": decrypted = blowfish_decrypt(bytes.fromhex(enc_text), BLOWFISH_KEY)
        elif algo == "RSA": decrypted = PKCS1_OAEP.new(SERVER_PRIVATE_KEY).decrypt(bytes.fromhex(enc_text)).decode()
        elif algo == "HILL": decrypted = hill_decrypt(enc_text.upper())
        elif algo == "COLUMNAR": decrypted = columnar_decrypt(enc_text.upper(), TRANS_KEY)
        elif algo == "RAILFENCE": decrypted = rail_fence_decrypt(enc_text.upper(), 3)
        elif algo == "SHIFT": decrypted = caesar_decrypt(enc_text.upper(), SHIFT_N)
        elif algo == "CAESAR": decrypted = caesar_decrypt(enc_text.upper(), 3)
        elif algo == "AFFINE": decrypted = affine_decrypt(enc_text.upper(), 5, 8)
        elif algo == "SUBSTITUTION": decrypted = substitution_decrypt(enc_text.upper(), SUB_KEY)
        elif algo == "VIGENERE": decrypted = vigenere_decrypt(enc_text.upper(), "KRIPTO")
        elif algo == "DES":
            c = DES.new(DES_KEY, DES.MODE_ECB)
            decrypted = unpad(c.decrypt(bytes.fromhex(enc_text)), DES.block_size).decode()
        elif algo == "ROUTE":
            decrypted = "Spiral Rota ile Deşifre Edildi (Geliştirme Aşamasında)"
            
        res = {"algo": algo, "encrypted": enc_text, "decrypted": decrypted, "mode": "Şifre Çözme"}
    except Exception as e:
        res = {"algo": algo, "error": "Hata: Geçersiz format veya anahtar!"}
    return render_template('index.html', result=res)

if __name__ == '__main__':
    app.run(debug=True)