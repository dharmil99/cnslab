# ==============================================================
# EXPERIMENT 8 : ECDSA  (P-256 / SHA-256)  - as in the submitted crypto_ops.py
# ==============================================================
# Classical signature, security = Elliptic Curve Discrete Log.
# Public key 91 B (DER), signature ~70-72 B (DER-encoded r, s).
# Broken by a large quantum computer (Shor's algorithm).
# Needs:  pip install cryptography
# ==============================================================

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


def keygen():
    sk = ec.generate_private_key(ec.SECP256R1())            # random key on curve P-256
    priv = sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub, priv                                        # keys as bytes (like the key files)


def sign(priv_bytes, message):
    sk = serialization.load_der_private_key(priv_bytes, password=None)
    return sk.sign(message, ec.ECDSA(hashes.SHA256()))


def verify(pub_bytes, message, signature):
    pk = serialization.load_der_public_key(pub_bytes)
    try:
        pk.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


if __name__ == "__main__":
    M = b"Transfer Rs.5000 to Account 1234"
    pub, priv = keygen()
    S = sign(priv, M)
    print("public key :", len(pub), "bytes   private key:", len(priv), "bytes   signature:", len(S), "bytes")
    print("verify original:", verify(pub, M, S))                                    # True
    print("verify tampered:", verify(pub, b"Transfer Rs.9000 to Account 1234", S))   # False
