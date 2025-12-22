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

import math

# --- COLUMNAR TRANSPOSITION ---
def columnar_encrypt(text, key="ANAHTAR"):
    text = text.replace(" ", "").upper()
    key = key.upper()
    n_cols = len(key)
    n_rows = math.ceil(len(text) / n_cols)
    
    # Boşlukları 'X' ile doldur (tam matris için)
    padding = n_rows * n_cols - len(text)
    text += "X" * padding
    
    # Matrisi oluştur
    matrix = [text[i:i + n_cols] for i in range(0, len(text), n_cols)]
    
    # Anahtar sırasını belirle (Örn: ANAHTAR -> A:0, A:2, A:5, H:3, N:1, R:6, T:4)
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    
    result = ""
    for col in key_order:
        for row in range(n_rows):
            result += matrix[row][col]
            
    return result

def columnar_decrypt(cipher, key="ANAHTAR"):
    key = key.upper()
    n_cols = len(key)
    n_rows = len(cipher) // n_cols
    
    # Anahtar sırasını belirle
    key_order = sorted(range(len(key)), key=lambda k: key[k])
    
    # Boş bir matris oluştur
    matrix = [['' for _ in range(n_cols)] for _ in range(n_rows)]
    
    # Şifreli metni sütun sütun yerleştir
    index = 0
    for col in key_order:
        for row in range(n_rows):
            matrix[row][col] = cipher[index]
            index += 1
            
    # Satır satır oku
    return "".join(["".join(row) for row in matrix])

# --- ROUTE CIPHER (Spiral Path) ---
def route_encrypt(text, cols=4):
    text = text.replace(" ", "").upper()
    rows = math.ceil(len(text) / cols)
    padding = rows * cols - len(text)
    text += "X" * padding  # Izgarayı doldur
    
    # Izgarayı oluştur
    grid = [list(text[i:i + cols]) for i in range(0, len(text), cols)]
    
    result = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    
    while top <= bottom and left <= right:
        # Üst satır (soldan sağa)
        for i in range(left, right + 1):
            result.append(grid[top][i])
        top += 1
        # Sağ sütun (yukarıdan aşağıya)
        for i in range(top, bottom + 1):
            result.append(grid[i][right])
        right -= 1
        # Alt satır (sağdan sola)
        if top <= bottom:
            for i in range(right, left - 1, -1):
                result.append(grid[bottom][i])
            bottom -= 1
        # Sol sütun (aşağıdan yukarıya)
        if left <= right:
            for i in range(bottom, top - 1, -1):
                result.append(grid[i][left])
            left += 1
            
    return "".join(result)

# --- PLAYFAIR CIPHER ---
def prepare_playfair_key(key):
    key = key.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ" # J hariç
    matrix = []
    used = set()
    
    for char in key + alphabet:
        if char not in used and char.isalpha():
            matrix.append(char)
            used.add(char)
    
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None

def playfair_encrypt(text, key="ANAHTAR"):
    matrix = prepare_playfair_key(key)
    text = text.upper().replace("J", "I").replace(" ", "")
    
    # İkili gruplar oluştur (Aynı harf yan yanaysa araya 'X' koy)
    prepared_text = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if (i+1) < len(text) else 'X'
        if a == b:
            prepared_text += a + 'X'
            i += 1
        else:
            prepared_text += a + b
            i += 2
    if len(prepared_text) % 2 != 0: prepared_text += 'X'

    result = ""
    for i in range(0, len(prepared_text), 2):
        r1, c1 = find_position(matrix, prepared_text[i])
        r2, c2 = find_position(matrix, prepared_text[i+1])
        
        if r1 == r2: # Aynı satır
            result += matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
        elif c1 == c2: # Aynı sütun
            result += matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
        else: # Dikdörtgen kuralı
            result += matrix[r1][c2] + matrix[r2][c1]
    return result

def playfair_decrypt(cipher, key="ANAHTAR"):
    matrix = prepare_playfair_key(key)
    result = ""
    for i in range(0, len(cipher), 2):
        r1, c1 = find_position(matrix, cipher[i])
        r2, c2 = find_position(matrix, cipher[i+1])
        
        if r1 == r2:
            result += matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]
        elif c1 == c2:
            result += matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]
        else:
            result += matrix[r1][c2] + matrix[r2][c1]
    return result

# --- POLYBIUS SQUARE CIPHER ---
def polybius_encrypt(text):
    text = text.upper().replace("J", "I").replace(" ", "")
    matrix = {
        'A':'11', 'B':'12', 'C':'13', 'D':'14', 'E':'15',
        'F':'21', 'G':'22', 'H':'23', 'I':'24', 'K':'25',
        'L':'31', 'M':'32', 'N':'33', 'O':'34', 'P':'35',
        'Q':'41', 'R':'42', 'S':'43', 'T':'44', 'U':'45',
        'V':'51', 'W':'52', 'X':'53', 'Y':'54', 'Z':'55'
    }
    result = ""
    for char in text:
        if char in matrix:
            result += matrix[char]
    return result

def polybius_decrypt(cipher):
    # Sayı çiftlerini harfe geri döndür
    reverse_matrix = {
        '11':'A', '12':'B', '13':'C', '14':'D', '15':'E',
        '21':'F', '22':'G', '23':'H', '24':'I', '25':'K',
        '31':'L', '32':'M', '33':'N', '34':'O', '35':'P',
        '41':'Q', '42':'R', '43':'S', '44':'T', '45':'U',
        '51':'V', '52':'W', '53':'X', '54':'Y', '55':'Z'
    }
    result = ""
    for i in range(0, len(cipher), 2):
        pair = cipher[i:i+2]
        if pair in reverse_matrix:
            result += reverse_matrix[pair]
    return result

# --- PIGPEN CIPHER ---
# Pigpen sembollerini temsil eden bir sözlük (Karakter -> Sembol Görünümü)
PIGPEN_DICT = {
    'A': '_|', 'B': '|_|', 'C': '|_',
    'D': '[|', 'E': '[-|', 'F': '[_',
    'G': '¯|', 'H': '|¯|', 'I': '|¯',
    'J': '_.', 'K': '|._|', 'L': '._',
    'M': '[.', 'N': '[-.]', 'O': '[._',
    'P': '¯.', 'Q': '|¯.|', 'R': '|¯.',
    'S': 'V',  'T': '>',   'U': '<',   'V': '^',
    'W': 'V.', 'X': '>.',  'Y': '<.',  'Z': '^.'
}

def pigpen_encrypt(text):
    text = text.upper().replace("İ", "I").replace("Ğ", "G").replace("Ü", "U").replace("Ş", "S").replace("Ö", "O").replace("Ç", "C")
    result = []
    for char in text:
        if char in PIGPEN_DICT:
            result.append(PIGPEN_DICT[char])
        else:
            result.append(char)
    return "  ".join(result)

def pigpen_decrypt(symbol_text):
    # Sembollerden harfe geri dönüş
    reverse_dict = {v: k for k, v in PIGPEN_DICT.items()}
    symbols = symbol_text.split("  ")
    result = ""
    for s in symbols:
        if s in reverse_dict:
            result += reverse_dict[s]
        else:
            result += s
    return result