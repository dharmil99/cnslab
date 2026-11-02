# ==============================================================
# EXPERIMENT 8 : SLH-DSA-SHA2-128s  (FIPS 205, post-quantum)  - as in the submitted crypto_ops.py
# ==============================================================
# Hash-based (hypertree of Merkle / FORS trees), old name SPHINCS+.
# Public key 32 B (tiny), private key 64 B, signature 7856 B (huge).
# Very slow signing (~0.5 s), fast verification. Security rests only on hash functions.
# Needs:  pip install liboqs-python
# ==============================================================

import oqs

ALG = "SLH_DSA_PURE_SHA2_128S"          # liboqs name


def keygen():
    with oqs.Signature(ALG) as signer:
        pk = signer.generate_keypair()
        return bytes(pk), bytes(signer.export_secret_key())


def sign(priv_bytes, message):
    signer = oqs.Signature(ALG, priv_bytes)
    return bytes(signer.sign(message))


def verify(pub_bytes, message, signature):
    verifier = oqs.Signature(ALG)
    try:
        return bool(verifier.verify(message, signature, pub_bytes))
    except Exception:
        return False


if __name__ == "__main__":
    M = b"Transfer Rs.5000 to Account 1234"
    pub, priv = keygen()
    S = sign(priv, M)                                   # takes ~0.5 s
    print("public key :", len(pub), "bytes   private key:", len(priv), "bytes   signature:", len(S), "bytes")
    print("verify original:", verify(pub, M, S))                                    # True
    print("verify tampered:", verify(pub, b"Transfer Rs.9000 to Account 1234", S))   # False
