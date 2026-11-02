# ==============================================================
# EXPERIMENT 2 : HILL CIPHER FOR ANY n x n MATRIX (3x3, 4x4, ...)
# ==============================================================
# THEORY:
#   Split the message into blocks of n letters (A=0 ... Z=25).
#   Encrypt each block P (a column of n numbers):   C = K x P  (mod 26)
#        c_i = (K[i][0]*p_0 + K[i][1]*p_1 + ... + K[i][n-1]*p_(n-1)) mod 26
#   Decrypt with the inverse matrix:                P = K^-1 x C (mod 26)
#
#   Inverse matrix mod 26:
#     1. det    = determinant of K, mod 26
#     2. det_inv = number with (det * det_inv) % 26 == 1
#        (exists only if gcd(det, 26) = 1, i.e. det is odd and not 13)
#     3. adj    = adjugate = transpose of the cofactor matrix
#                 cofactor C[i][j] = (-1)^(i+j) * det(minor without row i, col j)
#     4. K^-1   = det_inv * adj  (mod 26)
#
#   Determinant (Laplace expansion along the first row):
#     det(M) = sum over j of (-1)^j * M[0][j] * det(minor(M, 0, j))
#     1x1: det = the number,   2x2: det = a*d - b*c
#
#   Example 3x3 (key word "GYBNQKURP"):
#        K = | 6 24  1|      ACT -> POH,  CAT -> FIN
#            |13 16 10|      K^-1 = | 8  5 10|
#            |20 17 15|             |21  8 21|
#                                   |21 12  8|
# ==============================================================

import math
import random


def mod_inverse(a):
    a = a % 26
    for x in range(1, 26):                  # try every number
        if (a * x) % 26 == 1:
            return x
    return None                             # no inverse


def minor(M, row, col):
    # copy of M without the given row and column
    return [r[:col] + r[col + 1:] for i, r in enumerate(M) if i != row]


def determinant(M):
    n = len(M)
    if n == 1:
        return M[0][0]
    if n == 2:
        return M[0][0] * M[1][1] - M[0][1] * M[1][0]
    total = 0
    for j in range(n):                      # expand along the first row
        sign = (-1) ** j                    # + - + - ...
        total += sign * M[0][j] * determinant(minor(M, 0, j))
    return total


def is_valid_key(K):
    return math.gcd(determinant(K) % 26, 26) == 1


def inverse_key(K):
    n = len(K)
    det = determinant(K) % 26
    det_inv = mod_inverse(det)
    if det_inv is None:
        raise ValueError("key is not invertible mod 26 (gcd(det, 26) != 1)")
    inv = [[0] * n for i in range(n)]       # n x n matrix of zeros
    for i in range(n):
        for j in range(n):
            cofactor = (-1) ** (i + j) * determinant(minor(K, i, j))
            inv[j][i] = (det_inv * cofactor) % 26     # [j][i] = transpose (adjugate)
    return inv


def key_from_word(word, n):
    # first n*n letters of the word become the key, row by row
    nums = [ord(c) - 65 for c in word.upper() if c.isalpha()]
    return [nums[i * n:(i + 1) * n] for i in range(n)]


def random_key(n):
    # random n x n key that is invertible mod 26
    while True:
        K = [[random.randint(0, 25) for j in range(n)] for i in range(n)]
        if is_valid_key(K):
            return K


def prepare_text(text, n):
    clean = ""
    for ch in text.upper():
        if ch.isalpha():                    # letters only
            clean = clean + ch
    while len(clean) % n != 0:              # pad with X to a multiple of n
        clean = clean + "X"
    return clean


def hill_encrypt(text, key):
    n = len(key)
    text = prepare_text(text, n)
    result = ""
    for start in range(0, len(text), n):            # one block of n letters
        block = [ord(ch) - 65 for ch in text[start:start + n]]
        for i in range(n):                          # row i of the key x block
            total = 0
            for j in range(n):
                total += key[i][j] * block[j]
            result += chr(total % 26 + 65)
    return result


def hill_decrypt(text, key):
    return hill_encrypt(text, inverse_key(key))     # multiply by K^-1


if __name__ == "__main__":
    # 3x3 textbook example
    K3 = key_from_word("GYBNQKURP", 3)
    print("3x3 key     :", K3)
    print("det mod 26  :", determinant(K3) % 26)            # 25
    print("inverse key :", inverse_key(K3))                 # [[8, 5, 10], [21, 8, 21], [21, 12, 8]]
    print("ACT ->", hill_encrypt("ACT", K3))                # POH
    print("CAT ->", hill_encrypt("CAT", K3))                # FIN
    c = hill_encrypt("ATTACK AT DAWN", K3)
    print("ATTACK AT DAWN ->", c, "->", hill_decrypt(c, K3))

    # 4x4 random key
    K4 = random_key(4)
    print("\n4x4 key     :", K4)
    c = hill_encrypt("CRYPTOGRAPHY AND NETWORK SECURITY", K4)
    print("cipher      :", c)
    print("decrypted   :", hill_decrypt(c, K4))
