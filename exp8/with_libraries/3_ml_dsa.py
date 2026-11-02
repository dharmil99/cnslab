# ==============================================================
# EXPERIMENT 8 : ML-DSA-44  (FIPS 204, post-quantum)  - as in the submitted crypto_ops.py
# ==============================================================
# Lattice-based (Module-LWE / SIS), old name CRYSTALS-Dilithium.
# Public key 1312 B, private key 2560 B, signature 2420 B.
# Fast at everything, safe against Shor's algorithm.
# Needs:  pip install liboqs-python   (first import builds liboqs, a few minutes)
# ==============================================================

import oqs

ALG = "ML-DSA-44"


def keygen():
    with oqs.Signature(ALG) as signer:
        pk = signer.generate_keypair()                  # makes both keys, returns the public one
        return bytes(pk), bytes(signer.export_secret_key())


def sign(priv_bytes, message):
    signer = oqs.Signature(ALG, priv_bytes)             # load the private key
    return bytes(signer.sign(message))


def verify(pub_bytes, message, signature):
    verifier = oqs.Signature(ALG)                       # no private key needed
    try:
        return bool(verifier.verify(message, signature, pub_bytes))
    except Exception:
        return False


if __name__ == "__main__":
    M = b"Transfer Rs.5000 to Account 1234"
    pub, priv = keygen()
    S = sign(priv, M)
    print("public key :", len(pub), "bytes   private key:", len(priv), "bytes   signature:", len(S), "bytes")
    print("verify original:", verify(pub, M, S))                                    # True
    print("verify tampered:", verify(pub, b"Transfer Rs.9000 to Account 1234", S))   # False
