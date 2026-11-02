# ==============================================================
# EXPERIMENT 8 : RSA-PSS  (RSA-3072, e = 65537, SHA-256, MGF1, salt 32)
#                - as in the submitted crypto_ops.py
# ==============================================================
# Classical signature, security = integer factorisation.
# Public key 422 B (DER), signature 384 B. Slow key generation,
# very fast verification. Random salt -> different signature each time.
# Needs:  pip install cryptography
# ==============================================================

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)   # salt = digest length


def keygen():
    sk = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    priv = sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub, priv


def sign(priv_bytes, message):
    sk = serialization.load_der_private_key(priv_bytes, password=None)
    return sk.sign(message, PSS, hashes.SHA256())


def verify(pub_bytes, message, signature):
    pk = serialization.load_der_public_key(pub_bytes)
    try:
        pk.verify(signature, message, PSS, hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


if __name__ == "__main__":
    M = b"Transfer Rs.5000 to Account 1234"
    pub, priv = keygen()
    S = sign(priv, M)
    print("public key :", len(pub), "bytes   private key:", len(priv), "bytes   signature:", len(S), "bytes")
    print("same signature twice?", S == sign(priv, M))                              # False (salt)
    print("verify original:", verify(pub, M, S))                                    # True
    print("verify tampered:", verify(pub, b"Transfer Rs.9000 to Account 1234", S))   # False
