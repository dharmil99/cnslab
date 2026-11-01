# ==============================================================
# EXPERIMENT 8 : RSA-PSS DIGITAL SIGNATURE (3072-bit, SHA-256)
# ==============================================================
# THEORY:
#   RSA signature = RSA used "backwards":  s = hash^d mod n  (PRIVATE d)
#                   verify:  s^e mod n == hash ?             (PUBLIC e)
#   PSS adds a random SALT -> same message gives a DIFFERENT
#   signature each time (safer than plain RSA signing).
#     MGF1(SHA-256) = mask function used inside PSS
#     salt_length = 32 bytes
#   n = 3072 bits, e = 65537 -> signature = 384 bytes
#   Key generation is slow (finds two big primes), verification is fast.
#   Security: factoring (broken by quantum / Shor).
#
#   Library: cryptography      Install once:  pip install cryptography
# ==============================================================

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# PSS settings, used by both sign and verify
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def keygen():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()       # (e, n)
    return private_key, public_key


def sign(private_key, message):
    return private_key.sign(message, PSS, hashes.SHA256())


def verify(public_key, message, signature):
    try:
        public_key.verify(signature, message, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    M = b"Transfer Rs.5000 to Account 1234"
    private_key, public_key = keygen()
    S1 = sign(private_key, M)
    S2 = sign(private_key, M)
    print("signature size :", len(S1), "bytes")                         # 384
    print("same signature twice?", S1 == S2)                            # False (random salt)
    print("verify original:", verify(public_key, M, S1))                # True
    print("verify tampered:", verify(public_key, b"Transfer Rs.9000 to Account 1234", S1))  # False
