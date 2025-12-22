
# S-DES (SIMPLIFIED DATA ENCRYPTION STANDARD) - MANUEL MODÜL


# 1. Sabit Permütasyon Tabloları
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
P4 = (2, 4, 3, 1)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)

# S-Kutuları (S-Boxes)
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

def permute(bits, table):
    """Belirli bir tabloya göre bitleri yeniden sıralar."""
    return [bits[i - 1] for i in table]

def shift(bits, n):
    """Bitleri sola n kadar kaydırır."""
    return bits[n:] + bits[:n]

def key_generation(key_10bit):
    """10 bitlik anahtardan K1 ve K2 alt anahtarlarını üretir."""
    p10_key = permute(key_10bit, P10)
    left, right = p10_key[:5], p10_key[5:]
    
    # K1 Üretimi (Shift 1)
    left_s1, right_s1 = shift(left, 1), shift(right, 1)
    k1 = permute(left_s1 + right_s1, P8)
    
    # K2 Üretimi (Shift 2)
    left_s2, right_s2 = shift(left_s1, 2), shift(right_s1, 2)
    k2 = permute(left_s2 + right_s2, P8)
    
    return k1, k2

def f_k(bits, key):
    """S-DES Round fonksiyonu (fK)."""
    left, right = bits[:4], bits[4:]
    # Expansion Permutation (4 bit -> 8 bit)
    ep_bits = permute(right, EP)
    # XOR işlemi (Key ile)
    xor_bits = [b ^ k for b, k in zip(ep_bits, key)]
    
    l_xor, r_xor = xor_bits[:4], xor_bits[4:]
    
    # S0 Box İşlemi
    row0 = l_xor[0] * 2 + l_xor[3]
    col0 = l_xor[1] * 2 + l_xor[2]
    val0 = format(S0[row0][col0], '02b')
    
    # S1 Box İşlemi
    row1 = r_xor[0] * 2 + r_xor[3]
    col1 = r_xor[1] * 2 + r_xor[2]
    val1 = format(S1[row1][col1], '02b')
    
    # P4 Permütasyonu
    sbox_out = [int(b) for b in val0 + val1]
    p4_out = permute(sbox_out, P4)
    
    # Sol taraf ile XOR ve sağ tarafı ekleme
    return [b1 ^ b2 for b1, b2 in zip(left, p4_out)] + right

def sdes_encrypt_byte(byte_bits, k1, k2):
    """Tek bir byte (8-bit) için şifreleme işlemi."""
    bits = permute(byte_bits, IP)      # Initial Permutation
    bits = f_k(bits, k1)               # Round 1
    bits = bits[4:] + bits[:4]         # Switch (SW)
    bits = f_k(bits, k2)               # Round 2
    return permute(bits, IP_INV)       # Inverse Initial Permutation

# Flask Tarafından Çağrılan Fonksiyonlar

def encrypt_text(text):
    """Tüm metni S-DES ile şifreler ve Hex-Dashed formatta döner."""
    # Sabit Anahtar: 1010000010
    key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]
    k1, k2 = key_generation(key)
    
    encrypted_bytes = []
    for char in text:
        # Karakteri 8 bitlik listeye çevir
        bits = [int(b) for b in format(ord(char), '08b')]
        enc_bits = sdes_encrypt_byte(bits, k1, k2)
        # Hex formatına çevir (Örn: 'A3')
        hex_val = format(int("".join(map(str, enc_bits)), 2), '02X')
        encrypted_bytes.append(hex_val)
    
    return "-".join(encrypted_bytes)

def decrypt_text(hex_text):
    """Hex-Dashed formatındaki şifreli metni çözer."""
    key = [1, 0, 1, 0, 0, 0, 0, 0, 1, 0]
    k1, k2 = key_generation(key)
    
    decrypted_chars = []
    try:
        for h in hex_text.split("-"):
            if not h: continue
            # Hex değerini 8 bitlik listeye çevir
            bits = [int(b) for b in format(int(h, 16), '08b')]
            
            # Şifre çözmede k2 ve k1 sırası yer değiştirir
            b = permute(bits, IP)
            b = f_k(b, k2)             # Önce K2
            b = b[4:] + b[:4]          # Switch
            b = f_k(b, k1)             # Sonra K1
            dec_bits = permute(b, IP_INV)
            
            # Karakteri geri al
            decrypted_chars.append(chr(int("".join(map(str, dec_bits)), 2)))
        return "".join(decrypted_chars)
    except:
        return "[Hata: Geçersiz S-DES Formatı]"