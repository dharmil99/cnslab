# ==============================================================
# EXPERIMENT 7 : HMAC FROM SCRATCH  (RFC 2104)
#                for MD5, SHA-1, SHA-256, SHA-512 (hash from hashlib)
# ==============================================================
# THEORY:
#   HMAC(K, m) = H( (K XOR opad) + H( (K XOR ipad) + m ) )
#     - key longer than the hash block size -> hash it first
#     - pad the key with zero bytes up to the block size
#       (64 bytes for MD5 / SHA-1 / SHA-256, 128 bytes for SHA-512)
#     - ipad = 0x36 repeated,  opad = 0x5C repeated
#   Output size = output size of the hash (128 / 160 / 256 / 512 bits).
#
#   Receiver recomputes the HMAC and compares it with a CONSTANT-TIME
#   comparison (takes the same time whether the first byte or the last
#   byte differs, so an attacker learns nothing from timing).
# ==============================================================

import hashlib

BLOCK_SIZE = {"md5": 64, "sha1": 64, "sha256": 64, "sha512": 128}
IPAD, OPAD = 0x36, 0x5C


def hmac_bytes(key, message, algo):
    block = BLOCK_SIZE[algo]
    if len(key) > block:                        # long key -> hash it
        key = hashlib.new(algo, key).digest()
    key = key.ljust(block, b"\x00")             # pad with zero bytes to block size
    inner = hashlib.new(algo, bytes(k ^ IPAD for k in key) + message).digest()
    return hashlib.new(algo, bytes(k ^ OPAD for k in key) + inner).digest()


def constant_time_equal(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y                         # stays 0 only if every byte matches
    return result == 0


def verify_mac(key, algo, received_message, received_mac):
    return constant_time_equal(hmac_bytes(key, received_message, algo).hex(), received_mac)


def changed_bits(hex_a, hex_b):                 # avalanche: how many bits differ
    return bin(int(hex_a, 16) ^ int(hex_b, 16)).count("1")


if __name__ == "__main__":
    import hmac as std_hmac

    # RFC 4231 test case 2
    print("RFC 4231 vector OK:", hmac_bytes(b"Jefe", b"what do ya want for nothing?", "sha256").hex()
          == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

    key = b"secretkey"
    msg = b"Transfer Rs.5000 to Account 1234"
    for algo in BLOCK_SIZE:
        tag = hmac_bytes(key, msg, algo).hex()
        same = tag == std_hmac.new(key, msg, algo).hexdigest()
        print(f"HMAC-{algo:7} {len(tag) * 4:3} bits  matches hmac module: {same}")

    tag = hmac_bytes(key, msg, "sha256").hex()
    print("\nverify original :", verify_mac(key, "sha256", msg, tag))                         # True
    print("verify tampered :", verify_mac(key, "sha256", b"Transfer Rs.9000 to Account 1234", tag))   # False
    print("verify wrong key:", verify_mac(b"wrongkey", "sha256", msg, tag))                   # False
    other = hmac_bytes(key, b"Transfer Rs.5001 to Account 1234", "sha256").hex()
    print("bits changed by 1 character:", changed_bits(tag, other), "of 256")
