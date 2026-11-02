# ==============================================================
# EXPERIMENT 7 : SHA-512 FROM SCRATCH  (FIPS 180-4)   - 512-bit hash
# ==============================================================
# THEORY: exactly the same steps as SHA-256, but
#   - words are 64 bits (not 32)
#   - blocks are 128 bytes; pad until length is 112 mod 128, then a
#     16-byte bit length
#   - 80 rounds (not 64)
#   - rotation amounts:
#       schedule s0 = ror(1), ror(8), >>7      s1 = ror(19), ror(61), >>6
#       round    S0 = ror(28), ror(34), ror(39) S1 = ror(14), ror(18), ror(41)
#   - constants use 64 bits of the square / cube roots of the primes
#   SHA-512 is SECURE (and often faster than SHA-256 on 64-bit CPUs).
# ==============================================================

MASK64 = 0xFFFFFFFFFFFFFFFF


def iroot(n, k):                            # integer k-th root (Newton's method)
    if n < 2:
        return n
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y


def primes(count):
    found, n = [], 2
    while len(found) < count:
        if all(n % p for p in found if p * p <= n):
            found.append(n)
        n += 1
    return found


def frac_root_bits(p, k, bits):
    return iroot(p << (k * bits), k) & ((1 << bits) - 1)


P = primes(80)
H0 = [frac_root_bits(p, 2, 64) for p in P[:8]]         # 64-bit square-root constants
K = [frac_root_bits(p, 3, 64) for p in P[:80]]         # 64-bit cube-root constants


def ror(x, n):                              # rotate 64-bit x right by n
    return ((x >> n) | (x << (64 - n))) & MASK64


def pad(message):
    bit_length = len(message) * 8
    message = message + b"\x80"
    while len(message) % 128 != 112:
        message = message + b"\x00"
    return message + bit_length.to_bytes(16, "big")


def compress(state, block):
    W = [int.from_bytes(block[i:i + 8], "big") for i in range(0, 128, 8)]   # 16 words of 64 bits
    for t in range(16, 80):
        s0 = ror(W[t - 15], 1) ^ ror(W[t - 15], 8) ^ (W[t - 15] >> 7)
        s1 = ror(W[t - 2], 19) ^ ror(W[t - 2], 61) ^ (W[t - 2] >> 6)
        W.append((W[t - 16] + s0 + W[t - 7] + s1) & MASK64)

    a, b, c, d, e, f, g, h = state
    for t in range(80):
        S1 = ror(e, 14) ^ ror(e, 18) ^ ror(e, 41)
        ch = (e & f) ^ (~e & g)
        T1 = (h + S1 + ch + K[t] + W[t]) & MASK64
        S0 = ror(a, 28) ^ ror(a, 34) ^ ror(a, 39)
        maj = (a & b) ^ (a & c) ^ (b & c)
        T2 = (S0 + maj) & MASK64
        h, g, f, e = g, f, e, (d + T1) & MASK64
        d, c, b, a = c, b, a, (T1 + T2) & MASK64
    return [(x + y) & MASK64 for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def sha512(message):
    state = list(H0)
    data = pad(message)
    for i in range(0, len(data), 128):
        state = compress(state, data[i:i + 128])
    return b"".join(s.to_bytes(8, "big") for s in state).hex()


if __name__ == "__main__":
    import hashlib
    print("sha512('abc') =", sha512(b"abc")[:64], "...")
    # ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a...
    ok = all(sha512(m) == hashlib.sha512(m).hexdigest() for m in [b"", b"abc", b"x" * 1000])
    print("matches hashlib:", ok)
