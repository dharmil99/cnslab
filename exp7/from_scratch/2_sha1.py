# ==============================================================
# EXPERIMENT 7 : SHA-1 FROM SCRATCH  (FIPS 180-4)   - 160-bit hash
# ==============================================================
# THEORY:
#   1. PAD: 0x80, zeros until length is 56 mod 64, then the bit length
#      as 8 bytes (BIG-endian).
#   2. Each 64-byte block = 16 words; EXPAND to 80 words:
#        W[t] = rol(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16], 1)
#   3. State = 5 words (a, b, c, d, e). 80 rounds, 4 stages of 20:
#        0-19 : f = Ch  = (b AND c) XOR (NOT b AND d)    K = 0x5A827999
#        20-39: f = b XOR c XOR d (Parity)               K = 0x6ED9EBA1
#        40-59: f = Maj = (b AND c) XOR (b AND d) XOR (c AND d)  K = 0x8F1BBCDC
#        60-79: f = Parity                               K = 0xCA62C1D6
#      T = rol(a, 5) + f + e + K + W[t]
#      a, b, c, d, e = T, a, rol(b, 30), c, d
#   K values = 2^30 * sqrt(2), sqrt(3), sqrt(5), sqrt(10).
#   SHA-1 is BROKEN (SHAttered collision, 2017) - deprecated.
# ==============================================================

MASK32 = 0xFFFFFFFF
K = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK32


def pad(message):
    bit_length = len(message) * 8
    message = message + b"\x80"
    while len(message) % 64 != 56:
        message = message + b"\x00"
    return message + bit_length.to_bytes(8, "big")


def compress(state, block):
    W = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]   # 16 words
    for t in range(16, 80):                            # expand to 80 words
        W.append(rol(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1))
    a, b, c, d, e = state
    for t in range(80):
        if t < 20:
            f = (b & c) ^ (~b & d)                     # Ch
        elif t < 40:
            f = b ^ c ^ d                              # Parity
        elif t < 60:
            f = (b & c) ^ (b & d) ^ (c & d)            # Maj
        else:
            f = b ^ c ^ d                              # Parity
        T = (rol(a, 5) + (f & MASK32) + e + K[t // 20] + W[t]) & MASK32
        a, b, c, d, e = T, a, rol(b, 30), c, d
    return [(x + y) & MASK32 for x, y in zip(state, [a, b, c, d, e])]


def sha1(message):
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    data = pad(message)
    for i in range(0, len(data), 64):
        state = compress(state, data[i:i + 64])
    return b"".join(s.to_bytes(4, "big") for s in state).hex()


if __name__ == "__main__":
    import hashlib
    print("sha1('abc')         =", sha1(b"abc"))       # a9993e364706816aba3e25717850c26c9cd0d89d
    print("sha1('Hello World') =", sha1(b"Hello World"))
    ok = all(sha1(m) == hashlib.sha1(m).hexdigest() for m in [b"", b"abc", b"x" * 1000])
    print("matches hashlib     :", ok)
