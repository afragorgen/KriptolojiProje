import numpy as np
import math
from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP, DES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# --- ALFABE TANIMI ---
ALPHABET = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"
M = len(ALPHABET)

# ==========================================================
# 1. MODERN & ENDÜSTRİYEL ALGORİTMALAR (Kütüphane Destekli)
# ==========================================================

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

# ==========================================================
# 2. MATEMATİKSEL & BLOK KLASİKLERİ (Tamamen Manuel)
# ==========================================================

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

def playfair_encrypt(text, key="ANAHTAR"):
    matrix = prepare_playfair_key(key)
    text = text.upper().replace("J", "I").replace(" ", "")
    prepared_text = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if (i+1) < len(text) else 'X'
        if a == b:
            prepared_text += a + 'X'; i += 1
        else:
            prepared_text += a + b; i += 2
    if len(prepared_text) % 2 != 0: prepared_text += 'X'
    result = ""
    for i in range(0, len(prepared_text), 2):
        r1, c1 = find_position(matrix, prepared_text[i])
        r2, c2 = find_position(matrix, prepared_text[i+1])
        if r1 == r2: result += matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
        elif c1 == c2: result += matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
        else: result += matrix[r1][c2] + matrix[r2][c1]
    return result

def playfair_decrypt(cipher, key="ANAHTAR"):
    matrix = prepare_playfair_key(key)
    result = ""
    for i in range(0, len(cipher), 2):
        r1, c1 = find_position(matrix, cipher[i])
        r2, c2 = find_position(matrix, cipher[i+1])
        if r1 == r2: result += matrix[r1][(c1-1)%5] + matrix[r2][(c2-1)%5]
        elif c1 == c2: result += matrix[(r1-1)%5][c1] + matrix[(r2-1)%5][c2]
        else: result += matrix[r1][c2] + matrix[r2][c1]
    return result

def prepare_playfair_key(key):
    key = key.upper().replace("J", "I")
    abc = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = []
    used = set()
    for char in key + abc:
        if char not in used and char.isalpha():
            matrix.append(char); used.add(char)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char: return r, c
    return 0, 0

# ==========================================================
# 3. YER DEĞİŞTİRME / TRANSPOSITION (Tamamen Manuel)
# ==========================================================

def rail_fence_encrypt(text, rails=3):
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == 0 or rail == rails - 1: direction *= -1
    return "".join(["".join(r) for r in fence])

def rail_fence_decrypt(cipher, rails=3):
    fence = [['\n' for _ in range(len(cipher))] for _ in range(rails)]
    rail, direction = 0, 1
    for i in range(len(cipher)):
        fence[rail][i] = '*'; rail += direction
        if rail == 0 or rail == rails - 1: direction *= -1
    index = 0
    for r in range(rails):
        for c in range(len(cipher)):
            if fence[r][c] == '*' and index < len(cipher):
                fence[r][c] = cipher[index]; index += 1
    result = []; rail, direction = 0, 1
    for i in range(len(cipher)):
        result.append(fence[rail][i]); rail += direction
        if rail == 0 or rail == rails - 1: direction *= -1
    return "".join(result)

def columnar_encrypt(text, key="KRIPTO"):
    text = text.replace(" ", "").upper()
    n_cols = len(key)
    n_rows = math.ceil(len(text) / n_cols)
    text += "X" * (n_rows * n_cols - len(text))
    matrix = [text[i:i + n_cols] for i in range(0, len(text), n_cols)]
    key_order = sorted(range(len(key)), key=lambda k: key.upper()[k])
    return "".join(["".join(matrix[row][col] for row in range(n_rows)) for col in key_order])

def columnar_decrypt(cipher, key="KRIPTO"):
    n_cols = len(key)
    n_rows = len(cipher) // n_cols
    key_order = sorted(range(len(key)), key=lambda k: key.upper()[k])
    matrix = [['' for _ in range(n_cols)] for _ in range(n_rows)]
    index = 0
    for col in key_order:
        for row in range(n_rows):
            matrix[row][col] = cipher[index]; index += 1
    return "".join(["".join(row) for row in matrix])

def route_encrypt(text, cols=4):
    text = text.replace(" ", "").upper()
    rows = math.ceil(len(text) / cols)
    text += "X" * (rows * cols - len(text))
    grid = [list(text[i:i + cols]) for i in range(0, len(text), cols)]
    result = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    while top <= bottom and left <= right:
        for i in range(left, right + 1): result.append(grid[top][i])
        top += 1
        for i in range(top, bottom + 1): result.append(grid[i][right])
        right -= 1
        if top <= bottom:
            for i in range(right, left - 1, -1): result.append(grid[bottom][i])
            bottom -= 1
        if left <= right:
            for i in range(bottom, top - 1, -1): result.append(grid[i][left])
            left += 1
    return "".join(result)

# ==========================================================
# 4. KLASİK & SEMBOLİK YÖNTEMLER (Tamamen Manuel)
# ==========================================================

def caesar_encrypt(text, shift=3):
    res = ""
    for char in text.upper():
        if char in ALPHABET: res += ALPHABET[(ALPHABET.index(char) + shift) % M]
        else: res += char
    return res

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    res = ""; key = key.upper(); k_idx = 0
    for char in text.upper():
        if char in ALPHABET:
            shift = ALPHABET.index(key[k_idx % len(key)])
            res += ALPHABET[(ALPHABET.index(char) + shift) % M]; k_idx += 1
        else: res += char
    return res

def vigenere_decrypt(text, key):
    res = ""; key = key.upper(); k_idx = 0
    for char in text.upper():
        if char in ALPHABET:
            shift = ALPHABET.index(key[k_idx % len(key)])
            res += ALPHABET[(ALPHABET.index(char) - shift) % M]; k_idx += 1
        else: res += char
    return res

def affine_encrypt(text, a=5, b=8):
    res = ""
    for char in text.upper():
        if char in ALPHABET: res += ALPHABET[(a * ALPHABET.index(char) + b) % M]
        else: res += char
    return res

def affine_decrypt(text, a=5, b=8):
    def modInverse(a, m):
        for x in range(1, m):
            if (((a % m) * (x % m)) % m == 1): return x
        return -1
    a_inv = modInverse(a, M)
    res = ""
    for char in text.upper():
        if char in ALPHABET: res += ALPHABET[(a_inv * (ALPHABET.index(char) - b)) % M]
        else: res += char
    return res

def substitution_encrypt(text, key_alphabet):
    res = ""
    for char in text.upper():
        if char in ALPHABET: res += key_alphabet[ALPHABET.index(char)]
        else: res += char
    return res

def substitution_decrypt(text, key_alphabet):
    res = ""
    for char in text.upper():
        if char in key_alphabet: res += ALPHABET[key_alphabet.index(char)]
        else: res += char
    return res

def polybius_encrypt(text):
    text = text.upper().replace("J", "I").replace(" ", "")
    matrix = {'A':'11','B':'12','C':'13','D':'14','E':'15','F':'21','G':'22','H':'23','I':'24','K':'25','L':'31','M':'32','N':'33','O':'34','P':'35','Q':'41','R':'42','S':'43','T':'44','U':'45','V':'51','W':'52','X':'53','Y':'54','Z':'55'}
    return "".join([matrix.get(c, "") for c in text])

def polybius_decrypt(cipher):
    rev = {'11':'A','12':'B','13':'C','14':'D','15':'E','21':'F','22':'G','23':'H','24':'I','25':'K','31':'L','32':'M','33':'N','34':'O','35':'P','41':'Q','42':'R','43':'S','44':'T','45':'U','51':'V','52':'W','53':'X','54':'Y','55':'Z'}
    return "".join([rev.get(cipher[i:i+2], "") for i in range(0, len(cipher), 2)])

PIGPEN_DICT = {'A':'_|','B':'|_|','C':'|_','D':'[|','E':'[-|','F':'[_','G':'¯|','H':'|¯|','I':'|¯','J':'_.','K':'|._|','L':'._','M':'[.','N':'[-.]','O':'[._','P':'¯.','Q':'|¯.|','R':'|¯.','S':'V','T':'>','U':'<','V':'^','W':'V.','X':'>.','Y':'<.','Z':'^.'}

def pigpen_encrypt(text):
    text = text.upper().replace("İ","I").replace("Ğ","G").replace("Ü","U").replace("Ş","S").replace("Ö","O").replace("Ç","C")
    return "  ".join([PIGPEN_DICT.get(c, c) for c in text])

def pigpen_decrypt(symbol_text):
    rev = {v: k for k, v in PIGPEN_DICT.items()}
    return "".join([rev.get(s, s) for s in symbol_text.split("  ")])