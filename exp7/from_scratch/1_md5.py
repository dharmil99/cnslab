# ==============================================================
# EXPERIMENT 7 : MD5 FROM SCRATCH  (RFC 1321)   - 128-bit hash
# ==============================================================
# THEORY:
#   1. PAD the message: add byte 0x80, then zero bytes until the length
#      is 56 mod 64, then the message length in bits as 8 bytes (LITTLE-endian).
#   2. Split into 64-byte blocks; each block = 16 words of 32 bits.
#   3. State = 4 words (a, b, c, d). For each block run 64 steps
#      (4 rounds x 16), each round uses a different function:
#        round 1: F = (b AND c) OR (NOT b AND d)
#        round 2: G = (b AND d) OR (c AND NOT d)
#        round 3: H = b XOR c XOR d
#        round 4: I = c XOR (b OR NOT d)
#      a, b, c, d = d, b + rol(a + f + K[i] + M[g], s[i]), b, c
#   4. Add the result to the state; final state = the hash.
#   K[i] = floor(|sin(i+1)| * 2^32).   MD5 is BROKEN (collisions) - legacy only.
# ==============================================================

import math

MASK32 = 0xFFFFFFFF                                    # keep numbers 32-bit
K = [int(abs(math.sin(i + 1)) * 2 ** 32) & MASK32 for i in range(64)]
SHIFTS = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4


def rol(x, n):                                         # rotate 32-bit x left by n
    return ((x << n) | (x >> (32 - n))) & MASK32


def pad(message):
    bit_length = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    message = message + b"\x80"                        # one 1-bit, then zeros
    while len(message) % 64 != 56:
        message = message + b"\x00"
    return message + bit_length.to_bytes(8, "little")  # length at the end


def compress(state, block):
    M = [int.from_bytes(block[i:i + 4], "little") for i in range(0, 64, 4)]   # 16 words
    a, b, c, d = state
    for i in range(64):
        if i < 16:                                     # round 1
            f, g = (b & c) | (~b & d), i
        elif i < 32:                                   # round 2
            f, g = (b & d) | (c & ~d), (5 * i + 1) % 16
        elif i < 48:                                   # round 3
            f, g = b ^ c ^ d, (3 * i + 5) % 16
        else:                                          # round 4
            f, g = c ^ (b | (~d & MASK32)), (7 * i) % 16
        temp = (a + (f & MASK32) + K[i] + M[g]) & MASK32
        a, b, c, d = d, (b + rol(temp, SHIFTS[i])) & MASK32, b, c
    return [(x + y) & MASK32 for x, y in zip(state, [a, b, c, d])]


def md5(message):
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]    # starting values
    data = pad(message)
    for i in range(0, len(data), 64):                  # each 64-byte block
        state = compress(state, data[i:i + 64])
    return b"".join(s.to_bytes(4, "little") for s in state).hex()


if __name__ == "__main__":
    import hashlib
    print("md5('abc')         =", md5(b"abc"))         # 900150983cd24fb0d6963f7d28e17f72
    print("md5('Hello World') =", md5(b"Hello World"))
    ok = all(md5(m) == hashlib.md5(m).hexdigest() for m in [b"", b"abc", b"x" * 1000])
    print("matches hashlib    :", ok)
