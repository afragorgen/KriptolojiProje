import socket
import os
from crypto_utils import aes_encrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 65432))
    public_key_pem = client.recv(2048)
    public_key = RSA.import_key(public_key_pem)
    
    aes_key = os.urandom(16)
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    client.sendall(encrypted_aes_key)


    msg = "Selam hocam, bu mesaj AES ile şifrelendi!"
    encrypted_msg = aes_encrypt(msg, aes_key)
    client.sendall(encrypted_msg)
    print("[+] Şifreli mesaj gönderildi.")

    client.close()

if __name__ == "__main__":
    start_client()