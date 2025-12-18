# S-DES Tabloları
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8  = [6, 3, 7, 4, 8, 5, 10, 9]
P4  = [2, 4, 3, 1]
IP  = [2, 6, 3, 1, 4, 8, 5, 7]
IPI = [4, 1, 3, 5, 7, 2, 8, 6]
EP  = [4, 1, 2, 3, 2, 3, 4, 1]
S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

def permute(bits, table):
    return "".join([bits[i - 1] for i in table])

def left_shift(bits, n):
    return bits[n:] + bits[:n]

def xor(bits1, bits2):
    return "".join(['0' if b1 == b2 else '1' for b1, b2 in zip(bits1, bits2)])

def sbox(bits, sbox_table):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return '{:02b}'.format(sbox_table[row][col])

def generate_keys(key_10bit):
    p10_key = permute(key_10bit, P10)
    left, right = p10_key[:5], p10_key[5:]
    left, right = left_shift(left, 1), left_shift(right, 1)
    k1 = permute(left + right, P8)
    left, right = left_shift(left, 2), left_shift(right, 2)
    k2 = permute(left + right, P8)
    return k1, k2

def fk(bits, key):
    L, R = bits[:4], bits[4:]
    ep_r = permute(R, EP)
    xored = xor(ep_r, key)
    s_output = sbox(xored[:4], S0) + sbox(xored[4:], S1)
    p4_output = permute(s_output, P4)
    return xor(p4_output, L) + R

def sdes_encrypt(plaintext_8bit, key_10bit):
    k1, k2 = generate_keys(key_10bit)
    bits = permute(plaintext_8bit, IP)
    bits = fk(bits, k1)
    bits = bits[4:] + bits[:4] # Switch
    bits = fk(bits, k2)
    return permute(bits, IPI)

def encrypt_text(text, key_10bit="1010101010"):
    binary_res = ""
    for char in text:
        b_char = format(ord(char), '08b')
        binary_res += sdes_encrypt(b_char, key_10bit)
    return binary_res