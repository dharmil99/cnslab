# ==============================================================
# EXPERIMENT 7 : HMAC (Hash-based Message Authentication Code)
# ==============================================================
# THEORY:
#   HMAC = hash + SECRET KEY. Only someone with the key can make
#   or check the tag, so it gives INTEGRITY + AUTHENTICATION.
#
#   Formula (block size B = 64 bytes for SHA-256):
#     K' = key padded with zero bytes to 64 bytes
#          (if key is longer than 64 bytes, hash it first)
#     HMAC = H( (K' XOR opad) + H( (K' XOR ipad) + message ) )
#     ipad = byte 0x36 repeated,  opad = byte 0x5c repeated
#
#   Sender  : tag = HMAC(key, message), sends message + tag
#   Receiver: recomputes HMAC(key, message), compares with tag
#
#   Why not just hash(key + message)? It is open to a
#   "length extension attack"; the two-layer HMAC design prevents it.
#   HMAC vs signature: HMAC uses ONE shared key -> no non-repudiation.
# ==============================================================

import hmac
import hashlib


# --------------------------------------------------------------
# hmac_sha256 : using Python's built-in hmac module
# --------------------------------------------------------------
def hmac_sha256(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


# --------------------------------------------------------------
# hmac_manual : HMAC built by hand from the formula
# --------------------------------------------------------------
def hmac_manual(key, message):
    block = 64                                  # SHA-256 block size in bytes
    key = key.encode()
    message = message.encode()

    if len(key) > block:                        # long key -> hash it first
        key = hashlib.sha256(key).digest()
    key = key + b"\x00" * (block - len(key))    # pad with zero bytes to 64

    ipad = bytearray()
    opad = bytearray()
    for k in key:                               # each byte of the key
        ipad.append(k ^ 0x36)                   # key XOR 0x36
        opad.append(k ^ 0x5c)                   # key XOR 0x5c

    inner = hashlib.sha256(bytes(ipad) + message).digest()      # H(K'^ipad + m)
    return hashlib.sha256(bytes(opad) + inner).hexdigest()      # H(K'^opad + inner)


# --------------------------------------------------------------
# verify : receiver recomputes the tag and compares
# --------------------------------------------------------------
def verify(key, message, tag):
    return hmac.compare_digest(hmac_sha256(key, message), tag)
    # compare_digest = safe comparison (takes the same time either way)


if __name__ == "__main__":
    key = "secretkey"
    msg = "Transfer Rs.5000 to Account 1234"

    tag = hmac_sha256(key, msg)
    print("HMAC (built-in):", tag)
    print("HMAC (manual)  :", hmac_manual(key, msg))
    print("same?          :", tag == hmac_manual(key, msg))                     # True

    print("\nverify original     :", verify(key, msg, tag))                      # True
    print("verify tampered msg :", verify(key, "Transfer Rs.9000 to Account 1234", tag))   # False
    print("verify wrong key    :", verify("wrongkey", msg, tag))                 # False
