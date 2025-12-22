
# MANUAL S-DES (SIMPLIFIED DATA ENCRYPTION STANDARD)


# S-DES Sabitleri (Standart P-Kutuları ve S-Kutuları)
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
P4 = (2, 4, 3, 1)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)

S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

def permute(bits, table):
    return [bits[i - 1] for i in table]

def shift(bits, n):
    return bits[n:] + bits[:n]

def key_generation(key_10bit):
    # Anahtar üretimi: K1 ve K2
    p10_key = permute(key_10bit, P10)
    left, right = p10_key[:5], p10_key[5:]
    
    left_s1, right_s1 = shift(left, 1), shift(right, 1)
    k1 = permute(left_s1 + right_s1, P8)
    
    left_s2, right_s2 = shift(left_s1, 2), shift(right_s1, 2)
    k2 = permute(left_s2 + right_s2, P8)
    return k1, k2

def f_k(bits, key):
    left, right = bits[:4], bits[4:]
    ep_bits = permute(right, EP)
    xor_bits = [b ^ k for b, k in zip(ep_bits, key)]
    
    l_xor, r_xor = xor_bits[:4], xor_bits[4:]
    
    row0 = l_xor[0] * 2 + l_xor[3]
    col0 = l_xor[1] * 2 + l_xor[2]
    val0 = format(S0[row0][col0], '02b')
    
    row1 = r_xor[0] * 2 + r_xor[3]
    col1 = r_xor[1] * 2 + r_xor[2]
    val1 = format(S1[row1][col1], '02b')
    
    sbox_out = [int(b) for b in val0 + val1]
    p4_out = permute(sbox_out, P4)
    
    return [b1 ^ b2 for b1, b2 in zip(left, p4_out)] + right

def sdes_encrypt_byte(byte_bits, k1, k2):
    bits = permute(byte_bits, IP)
    bits = f_k(bits, k1)
    bits = bits[4:] + bits[:4] # Swap
    bits = f_k(bits, k2)
    return permute(bits, IP_INV)

# Flask app.py tarafında çağrılan ana fonksiyon
def encrypt_text(text):
    # Örnek sabit 10-bit anahtar: 1010000010
    key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]
    k1, k2 = key_generation(key)
    
    encrypted_bytes = []
    for char in text:
        # Harfi 8-bitlik listeye çevir
        bits = [int(b) for b in format(ord(char), '08b')]
        enc_bits = sdes_encrypt_byte(bits, k1, k2)
        # Bitleri tekrar sayıya ve karakterin hex karşılığına çevir
        encrypted_bytes.append(format(int("".join(map(str, enc_bits)), 2), '02X'))
    
    return "-".join(encrypted_bytes)

def decrypt_text(hex_text):
    # Örnek sabit anahtar
    key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]
    k1, k2 = key_generation(key)
    
    decrypted_chars = []
    for h in hex_text.split("-"):
        bits = [int(b) for b in format(int(h, 16), '08b')]
        # Çözme sırasında anahtarların sırası yer değiştirir (k2, sonra k1)
        bits = permute(bits, IP)
        bits = f_k(bits, k2)
        bits = bits[4:] + bits[:4] # Swap
        bits = f_k(bits, k1)
        dec_bits = permute(bits, IP_INV)
        decrypted_chars.append(chr(int("".join(map(str, dec_bits)), 2)))
    
    return "".join(decrypted_chars)