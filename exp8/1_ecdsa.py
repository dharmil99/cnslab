# ==============================================================
# EXPERIMENT 8 : ECDSA DIGITAL SIGNATURE (P-256 curve, SHA-256)
# ==============================================================
# THEORY:
#   Digital signature = proves WHO sent it + that it was NOT changed
#   + sender cannot deny it (non-repudiation).
#     KeyGen : private key d (number), public key Q = d*G (point)
#     Sign   : with the PRIVATE key  (sender)
#     Verify : with the PUBLIC key   (receiver)
#   Signature = two numbers (r, s) -> about 70 bytes (very small)
#   Security: Elliptic Curve Discrete Log (broken by quantum / Shor).
#
#   Library: cryptography      Install once:  pip install cryptography
#   verify() returns nothing if OK, RAISES InvalidSignature if not.
# ==============================================================

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


def keygen():
    private_key = ec.generate_private_key(ec.SECP256R1())  # random key on P-256
    public_key = private_key.public_key()                   # Q = d*G
    return private_key, public_key


def sign(private_key, message):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))   # hash with SHA-256, then sign


def verify(public_key, message, signature):
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True                     # no error -> valid
    except InvalidSignature:
        return False                    # error -> invalid


if __name__ == "__main__":
    M = b"Transfer Rs.5000 to Account 1234"     # b"" = bytes
    private_key, public_key = keygen()
    S = sign(private_key, M)
    print("signature size :", len(S), "bytes")                          # ~70
    print("verify original:", verify(public_key, M, S))                 # True
    print("verify tampered:", verify(public_key, b"Transfer Rs.9000 to Account 1234", S))   # False
    _, other_public_key = keygen()
    print("verify wrong key:", verify(other_public_key, M, S))          # False
