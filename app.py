import os
import sys
from flask import Flask, render_template, request

# --- HATA ENGELLEYİCİ: Dosya yolunu Python'a zorla tanıtıyoruz ---
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    from crypto_utils import aes_encrypt, aes_decrypt, generate_rsa_keys
    from manual_sdes import encrypt_text as sdes_encrypt_manual
    print(">>> MODÜLLER BAŞARIYLA YÜKLENDİ")
except ImportError as e:
    print(f">>> KRİTİK HATA: Modüller yüklenemedi! Hata detayı: {e}")

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# --- ANAHTARLAR (ÖDEV GEREKSİNİMLERİ) ---
AES_KEY = b'16byte_uzun_key!' # 16 byte
DES_KEY = b'8byt_key'          # 8 byte

# RSA Hazırlığı
PRIVATE_KEY_PEM, PUBLIC_KEY_PEM = generate_rsa_keys()
SERVER_PRIVATE_KEY = RSA.import_key(PRIVATE_KEY_PEM)
SERVER_PUBLIC_KEY = RSA.import_key(PUBLIC_KEY_PEM)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/send', methods=['POST'])
def send():
    msg = request.form.get('message', '')
    algo = request.form.get('algo', 'AES')
    encrypted = ""
    decrypted = ""

    try:
        if algo == "AES":
            enc_bytes = aes_encrypt(msg, AES_KEY)
            encrypted = enc_bytes.hex()
            decrypted = aes_decrypt(enc_bytes, AES_KEY)

        elif algo == "DES":
            cipher = DES.new(DES_KEY, DES.MODE_ECB)
            enc_bytes = cipher.encrypt(pad(msg.encode(), DES.block_size))
            encrypted = enc_bytes.hex()
            decrypted = unpad(cipher.decrypt(enc_bytes), DES.block_size).decode()

        elif algo == "SDES":
            # Manuel S-DES Fonksiyonu
            encrypted = sdes_encrypt_manual(msg)
            decrypted = "[MANUEL MOD: Şifreleme Tamamlandı]"

        elif algo == "RSA":
            cipher_rsa = PKCS1_OAEP.new(SERVER_PUBLIC_KEY)
            enc_bytes = cipher_rsa.encrypt(msg.encode())
            encrypted = enc_bytes.hex()
            # Çözme
            decrypt_rsa = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)
            decrypted = decrypt_rsa.decrypt(enc_bytes).decode()

    except Exception as e:
        encrypted = "Hata!"
        decrypted = str(e)

    result = {
        "algo": algo,
        "original": msg,
        "encrypted": encrypted,
        "decrypted": decrypted
    }
    
    return render_template('index.html', result=result)

if __name__ == '__main__':
    print(">>> Flask Sunucusu Başlatılıyor: http://127.0.0.1:5000")
    app.run(debug=True)