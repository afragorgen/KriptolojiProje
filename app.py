import os
import sys
from flask import Flask, render_template, request

# --- IMPORT HATA ÇÖZÜCÜ ---
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    from crypto_utils import (
        aes_encrypt, aes_decrypt, 
        generate_rsa_keys, 
        caesar_encrypt, caesar_decrypt,
        vigenere_encrypt, vigenere_decrypt
    )
    from manual_sdes import encrypt_text as sdes_encrypt_manual
    print(">>> [BAŞARILI] Tüm kripto modülleri yüklendi.")
except ImportError as e:
    print(f">>> [HATA] Modül yükleme hatası: {e}")

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, template_folder=os.path.join(current_dir, 'templates'))

# --- ANAHTARLAR ---
AES_KEY = b'16byte_uzun_key!' # 128-bit
DES_KEY = b'8byt_key'          # 64-bit

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
        # 1. CAESAR (Klasik)
        if algo == "CAESAR":
            shift = 3
            encrypted = caesar_encrypt(msg, shift)
            decrypted = caesar_decrypt(encrypted, shift)

        # 2. VIGENERE (Polialfabetik)
        elif algo == "VIGENERE":
            v_key = "KRIPTO" # Deftere not et: Vigenere anahtarı
            encrypted = vigenere_encrypt(msg, v_key)
            decrypted = vigenere_decrypt(encrypted, v_key)

        # 3. AES (Modern Simetrik)
        elif algo == "AES":
            enc_bytes = aes_encrypt(msg, AES_KEY)
            encrypted = enc_bytes.hex()
            decrypted = aes_decrypt(enc_bytes, AES_KEY)

        # 4. DES (Standart Simetrik)
        elif algo == "DES":
            cipher = DES.new(DES_KEY, DES.MODE_ECB)
            enc_bytes = cipher.encrypt(pad(msg.encode(), DES.block_size))
            encrypted = enc_bytes.hex()
            decrypted = unpad(cipher.decrypt(enc_bytes), DES.block_size).decode()

        # 5. SDES (Manuel Uygulama)
        elif algo == "SDES":
            encrypted = sdes_encrypt_manual(msg)
            decrypted = "[MANUEL S-DES: İşlem terminalden izlenebilir]"

        # 6. RSA (Asimetrik)
        elif algo == "RSA":
            cipher_rsa = PKCS1_OAEP.new(SERVER_PUBLIC_KEY)
            enc_bytes = cipher_rsa.encrypt(msg.encode())
            encrypted = enc_bytes.hex()
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
    app.run(debug=True)