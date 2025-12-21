import os
import sys
from flask import Flask, render_template, request

# ==========================================
# ÇALIŞMA DİZİNİ VE IMPORT AYARI
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

try:
    from crypto_utils import (
        aes_encrypt, aes_decrypt, generate_rsa_keys, 
        caesar_encrypt, caesar_decrypt, vigenere_encrypt, vigenere_decrypt,
        substitution_encrypt, substitution_decrypt
    )
    from manual_sdes import encrypt_text as sdes_encrypt_manual
    print(">>> [BAŞARILI] Tüm modüller (Substitution dahil) yüklendi.")
except ImportError as e:
    print(f">>> [HATA] Modül yüklenemedi: {e}")

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

# --- ANAHTARLAR ---
AES_KEY = b'16byte_uzun_key!'
DES_KEY = b'8byt_key'
# Substitution için rastgele karıştırılmış alfabe (Anahtar)
SUB_KEY = "QWERTYUIOPĞÜASDFGHJKLŞİZXCVBNM " 

PRIVATE_KEY_PEM, PUBLIC_KEY_PEM = generate_rsa_keys()
SERVER_PRIVATE_KEY = RSA.import_key(PRIVATE_KEY_PEM)
SERVER_PUBLIC_KEY = RSA.import_key(PUBLIC_KEY_PEM)

@app.route('/')
def index():
    return render_template('index.html')

# ==========================================
#  ŞİFRELEME (SEND)
# ==========================================
@app.route('/send', methods=['POST'])
def send():
    msg = request.form.get('message', '').upper() # Substitution için büyük harf standardı
    algo = request.form.get('algo', 'AES')
    try:
        if algo == "SUBSTITUTION":
            encrypted = substitution_encrypt(msg, SUB_KEY)
            decrypted = substitution_decrypt(encrypted, SUB_KEY)
        elif algo == "CAESAR":
            encrypted = caesar_encrypt(msg, 3)
            decrypted = caesar_decrypt(encrypted, 3)
        elif algo == "VIGENERE":
            encrypted = vigenere_encrypt(msg, "KRIPTO")
            decrypted = vigenere_decrypt(encrypted, "KRIPTO")
        elif algo == "AES":
            enc_b = aes_encrypt(msg, AES_KEY); encrypted = enc_b.hex()
            decrypted = aes_decrypt(enc_b, AES_KEY)
        elif algo == "DES":
            c = DES.new(DES_KEY, DES.MODE_ECB)
            enc_b = c.encrypt(pad(msg.encode(), DES.block_size)); encrypted = enc_b.hex()
            decrypted = unpad(c.decrypt(enc_b), DES.block_size).decode()
        elif algo == "SDES":
            encrypted = sdes_encrypt_manual(msg); decrypted = "[Terminale Bakın]"
        elif algo == "RSA":
            c = PKCS1_OAEP.new(SERVER_PUBLIC_KEY); enc_b = c.encrypt(msg.encode())
            encrypted = enc_b.hex(); decrypted = PKCS1_OAEP.new(SERVER_PRIVATE_KEY).decrypt(enc_b).decode()
        
        res = {"algo": algo, "original": msg, "encrypted": encrypted, "decrypted": decrypted, "mode": "Şifreleme"}
    except Exception as e:
        res = {"algo": algo, "error": f"Hata: {str(e)}"}
    return render_template('index.html', result=res)

# ==========================================
#  ŞİFRE ÇÖZME (DECRYPT)
# ==========================================
@app.route('/decrypt', methods=['POST'])
def decrypt_direct():
    enc_text = request.form.get('encrypted_message', '').strip().upper()
    algo = request.form.get('algo', 'AES')
    try:
        if algo == "SUBSTITUTION":
            decrypted = substitution_decrypt(enc_text, SUB_KEY)
        elif algo == "CAESAR":
            decrypted = caesar_decrypt(enc_text, 3)
        elif algo == "VIGENERE":
            decrypted = vigenere_decrypt(enc_text, "KRIPTO")
        elif algo in ["AES", "DES", "RSA"]:
            enc_b = bytes.fromhex(enc_text)
            if algo == "AES": decrypted = aes_decrypt(enc_b, AES_KEY)
            elif algo == "DES":
                c = DES.new(DES_KEY, DES.MODE_ECB)
                decrypted = unpad(c.decrypt(enc_b), DES.block_size).decode()
            elif algo == "RSA": decrypted = PKCS1_OAEP.new(SERVER_PRIVATE_KEY).decrypt(enc_b).decode()
        
        res = {"algo": algo, "original": "Dış Veri", "encrypted": enc_text, "decrypted": decrypted, "mode": "Şifre Çözme"}
    except Exception as e:
        res = {"algo": algo, "error": "Geçersiz format veya anahtar!"}
    
    return render_template('index.html', result=res)

if __name__ == '__main__':
    app.run(debug=True)