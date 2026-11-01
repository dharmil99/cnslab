# ==============================================================
# EXPERIMENT 3 : RSA
# ==============================================================
# THEORY:
#   KEY GENERATION
#     1. two primes p and q
#     2. n   = p * q
#     3. phi = (p-1) * (q-1)
#     4. e with gcd(e, phi) = 1
#     5. d with (e * d) mod phi = 1       (inverse of e)
#     Public key = (e, n)     Private key = (d, n)
#   ENCRYPT : c = m^e mod n       (m < n)
#   DECRYPT : m = c^d mod n
#   Security: to find d you need phi -> need p, q -> must FACTOR n.
#
#   Example: p=3, q=11 -> n=33, phi=20, e=7 -> d=3
#            m=2 -> c = 2^7 mod 33 = 29 -> 29^3 mod 33 = 2
# ==============================================================

import math         # for math.gcd()


def mod_inverse(e, phi):
    for d in range(1, phi):             # try d = 1, 2, 3, ...
        if (e * d) % phi == 1:          # does it undo e?
            return d
    return None                         # no inverse


def generate_keys(p, q, e):
    n = p * q                           # public modulus
    phi = (p - 1) * (q - 1)             # secret
    if math.gcd(e, phi) != 1:           # e must share no factor with phi
        raise ValueError("e is not coprime to phi")
    d = mod_inverse(e, phi)             # private exponent
    return n, phi, d


def rsa_encrypt(m, e, n):
    return pow(m, e, n)                 # c = m^e mod n


def rsa_decrypt(c, d, n):
    return pow(c, d, n)                 # m = c^d mod n


if __name__ == "__main__":
    n, phi, d = generate_keys(3, 11, 7)         # n=33, phi=20, d=3
    c = rsa_encrypt(2, 7, n)                    # encrypt m = 2
    print("n =", n, " phi =", phi, " d =", d)
    print("m = 2 -> c =", c, "-> decrypted =", rsa_decrypt(c, d, n))
