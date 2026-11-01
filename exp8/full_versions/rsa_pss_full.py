# ==============================================================
# EXPERIMENT 8 : RSA-PSS FROM SCRATCH  (SHA-256, MGF1, 32-byte salt)
#                only hashlib (SHA-256), os.urandom and random are used
# ==============================================================
# THEORY:
#   RSA keys (Exp 3): n = p*q, e = 65537, d = e^-1 mod phi
#   RSA signature   : s = EM^d mod n   (PRIVATE d)
#           verify  : EM = s^e mod n   (PUBLIC e), then check EM
#
#   PSS = "Probabilistic Signature Scheme". Instead of signing the hash
#   directly, we build an "encoded message" EM with a random SALT:
#
#     mHash = SHA-256(message)
#     M'    = 8 zero bytes + mHash + salt
#     H     = SHA-256(M')
#     DB    = zero bytes (padding) + 0x01 + salt
#     maskedDB = DB XOR MGF1(H)          (hides the salt)
#     EM    = maskedDB + H + 0xBC
#
#   MGF1(seed, length) = SHA-256(seed + counter 0) + SHA-256(seed + counter 1) + ...
#                        cut to the wanted length  ("Mask Generation Function")
#
#   Random salt -> same message gives a DIFFERENT signature each time.
#   Verify = undo the steps, get the salt back, rebuild H, compare.
#
#   Primes are made with MILLER-RABIN (Exp 1).
#   d is found with pow(e, -1, phi): numbers are ~2048 bits, so the
#   "try every d" loop from Exp 3 would never finish.
# ==============================================================

import hashlib
import os
import random

HLEN = 32           # SHA-256 output size in bytes
SLEN = 32           # salt length in bytes
rng = random.SystemRandom()


# ================= KEY GENERATION =================

def is_probable_prime(n, k=20):
    """Miller-Rabin (Exp 1)."""
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % small == 0:
            return n == small               # quick check with small primes
    d, r = n - 1, 0
    while d % 2 == 0:                       # n-1 = 2^r * d
        d //= 2
        r += 1
    for i in range(k):
        x = pow(rng.randint(2, n - 2), d, n)
        if x == 1 or x == n - 1:
            continue
        for j in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:                               # loop ended without reaching n-1
            return False
    return True


def random_prime(bits):
    while True:
        c = rng.getrandbits(bits) | (1 << (bits - 1)) | 1   # top bit set (right size), odd
        if is_probable_prime(c):
            return c


def keygen(bits=2048, e=65537):
    while True:
        p = random_prime(bits // 2)
        q = random_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e != 0:         # e must be coprime to phi (e is prime)
            break
    n = p * q
    d = pow(e, -1, phi)                     # private exponent
    return (e, n), (d, n)                   # public key, private key


# ================= PSS ENCODING =================

def mgf1(seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def xor_bytes(x, y):
    result = bytearray()
    for i in range(len(x)):
        result.append(x[i] ^ y[i])          # XOR byte by byte
    return bytes(result)


def pss_encode(message, em_bits):
    em_len = (em_bits + 7) // 8                     # bytes needed for em_bits
    m_hash = hashlib.sha256(message).digest()
    salt = os.urandom(SLEN)                         # random salt
    H = hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest()
    PS = b"\x00" * (em_len - SLEN - HLEN - 2)       # zero padding
    DB = PS + b"\x01" + salt
    masked_db = bytearray(xor_bytes(DB, mgf1(H, em_len - HLEN - 1)))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)  # clear extra top bits
    return bytes(masked_db) + H + b"\xbc"


def pss_verify(message, EM, em_bits):
    em_len = (em_bits + 7) // 8
    if len(EM) != em_len or EM[-1] != 0xBC:         # must end with 0xBC
        return False
    masked_db = EM[:em_len - HLEN - 1]
    H = EM[em_len - HLEN - 1:-1]
    DB = bytearray(xor_bytes(masked_db, mgf1(H, em_len - HLEN - 1)))   # undo the mask
    DB[0] &= 0xFF >> (8 * em_len - em_bits)
    ps_len = em_len - HLEN - SLEN - 2
    if DB[:ps_len] != b"\x00" * ps_len or DB[ps_len] != 0x01:
        return False                                # padding is wrong
    salt = bytes(DB[-SLEN:])                        # salt recovered
    m_hash = hashlib.sha256(message).digest()
    H2 = hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest()
    return H == H2                                  # rebuilt hash must match


# ================= SIGN / VERIFY =================

def sign(private_key, message):
    d, n = private_key
    mod_bits = n.bit_length()
    EM = pss_encode(message, mod_bits - 1)
    m = int.from_bytes(EM, "big")                   # bytes -> number
    s = pow(m, d, n)                                # RSA with PRIVATE d
    return s.to_bytes((mod_bits + 7) // 8, "big")   # number -> bytes


def verify(public_key, message, signature):
    e, n = public_key
    mod_bits = n.bit_length()
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    m = pow(s, e, n)                                # RSA with PUBLIC e
    em_bits = mod_bits - 1
    EM = m.to_bytes((em_bits + 7) // 8, "big")
    return pss_verify(message, EM, em_bits)


if __name__ == "__main__":
    M = b"Transfer Rs.5000 to Account 1234"
    public_key, private_key = keygen(2048)          # lab used 3072: keygen(3072), slower
    S1 = sign(private_key, M)
    S2 = sign(private_key, M)
    print("modulus size   :", public_key[1].bit_length(), "bits")
    print("signature size :", len(S1), "bytes")                             # 256
    print("same signature twice?", S1 == S2)                                # False (random salt)
    print("verify original:", verify(public_key, M, S1))                    # True
    print("verify tampered:", verify(public_key, b"Transfer Rs.9000 to Account 1234", S1))  # False
