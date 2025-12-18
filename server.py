import socket
from crypto_utils import generate_rsa_keys, aes_decrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def start_server():
    print("[*] Sunucu: RSA anahtarları hazırlanıyor...")
    private_key_pem, public_key_pem = generate_rsa_keys()
    private_key = RSA.import_key(private_key_pem)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 65432))
    server.listen(1)
    print("[*] Sunucu dinlemede (127.0.0.1:65432)...")

    conn, addr = server.accept()
    print(f"[+] Bağlantı sağlandı: {addr}")

    conn.sendall(public_key_pem)

    encrypted_aes_key = conn.recv(256)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    print(f"[!] AES Anahtarı başarıyla alındı: {aes_key.hex()}")

    encrypted_msg = conn.recv(1024)
    decrypted_msg = aes_decrypt(encrypted_msg, aes_key)
    print(f"[SUCCESS] Mesaj Çözüldü: {decrypted_msg}")

    conn.close()

if __name__ == "__main__":
    start_server()