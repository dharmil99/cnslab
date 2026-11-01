# ==============================================================
# EXPERIMENT 8 : RSA-PSS - SIMPLEST VERSION (only hashlib for SHA-256)
# ==============================================================
# RSA keys (Exp 3):  n = p*q, e = 65537, d = e^-1 mod phi
#
# PSS SIGN:
#   salt = 32 random bytes
#   H    = SHA256( 8 zero bytes + SHA256(message) + salt )
#   DB   = zero bytes + 0x01 + salt
#   EM   = (DB XOR MGF1(H)) + H + 0xBC        (MGF1 hides the salt)
#   signature s = EM^d mod n                    (PRIVATE key)
#
# PSS VERIFY:
#   EM = s^e mod n                              (PUBLIC key)
#   split EM -> maskedDB, H, last byte (must be 0xBC)
#   DB = maskedDB XOR MGF1(H)   -> salt = last 32 bytes of DB
#   valid if H == SHA256( 8 zero bytes + SHA256(message) + salt )
#
# MGF1(seed, length) = SHA256(seed+0) + SHA256(seed+1) + ...  cut to length
#
# Random salt -> same message gives a DIFFERENT signature each time.
# Simplification: EM is made 1 byte shorter than n so that EM < n
# (the official standard trims single bits instead - see full_versions/).
# ==============================================================

import hashlib
import os
import random


def sha256(data):
    return hashlib.sha256(data).digest()


# ---------------- RSA keys ----------------
def is_prime(n):                            # Fermat test from Exp 1 (base 2)
    return pow(2, n - 1, n) == 1


def random_prime(bits):
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1   # right size, odd
        if is_prime(n):
            return n


def keygen(bits=1024):
    e = 65537
    while True:
        p, q = random_prime(bits // 2), random_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e != 0:         # e must not divide phi
            break
    d = pow(e, -1, phi)                     # inverse (numbers too big for a loop)
    return (e, p * q), (d, p * q)           # public, private


# ---------------- PSS helpers ----------------
def mgf1(seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += sha256(seed + counter.to_bytes(4, "big"))
        counter += 1
    return out[:length]


def xor(x, y):
    return bytes(i ^ j for i, j in zip(x, y))    # XOR byte by byte


# ---------------- sign / verify ----------------
def sign(private_key, message):
    d, n = private_key
    em_len = (n.bit_length() + 7) // 8 - 1      # 1 byte shorter than n
    salt = os.urandom(32)
    H = sha256(b"\x00" * 8 + sha256(message) + salt)
    DB = b"\x00" * (em_len - 32 - 32 - 2) + b"\x01" + salt
    EM = xor(DB, mgf1(H, len(DB))) + H + b"\xbc"
    return pow(int.from_bytes(EM, "big"), d, n)  # s = EM^d mod n


def verify(public_key, message, s):
    e, n = public_key
    em_len = (n.bit_length() + 7) // 8 - 1
    m = pow(s, e, n)                             # EM = s^e mod n
    if m >= 256 ** em_len:                       # too big -> not a real EM
        return False
    EM = m.to_bytes(em_len, "big")
    masked_db, H, last = EM[:-33], EM[-33:-1], EM[-1]
    DB = xor(masked_db, mgf1(H, len(masked_db)))     # undo the mask
    salt = DB[-32:]
    return last == 0xBC and DB[-33] == 1 and H == sha256(b"\x00" * 8 + sha256(message) + salt)


if __name__ == "__main__":
    M = b"Transfer Rs.5000 to Account 1234"
    public_key, private_key = keygen()
    s1 = sign(private_key, M)
    s2 = sign(private_key, M)
    print("same signature twice?", s1 == s2)                                    # False
    print("verify original:", verify(public_key, M, s1))                        # True
    print("verify tampered:", verify(public_key, b"Transfer Rs.9000 to Account 1234", s1))   # False
