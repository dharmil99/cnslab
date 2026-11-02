# ==============================================================
# EXPERIMENT 7 : SHA-256 FROM SCRATCH  (FIPS 180-4)   - 256-bit hash
# ==============================================================
# THEORY:
#   1. PAD: 0x80, zeros until length is 56 mod 64, then bit length (8 bytes, big-endian).
#   2. Each 64-byte block = 16 words; MESSAGE SCHEDULE expands to 64 words:
#        s0 = ror(W[t-15],7) XOR ror(W[t-15],18) XOR (W[t-15] >> 3)
#        s1 = ror(W[t-2],17) XOR ror(W[t-2],19)  XOR (W[t-2] >> 10)
#        W[t] = W[t-16] + s0 + W[t-7] + s1
#   3. State = 8 words (a..h). 64 rounds:
#        S1  = ror(e,6) XOR ror(e,11) XOR ror(e,25)
#        ch  = (e AND f) XOR (NOT e AND g)
#        T1  = h + S1 + ch + K[t] + W[t]
#        S0  = ror(a,2) XOR ror(a,13) XOR ror(a,22)
#        maj = (a AND b) XOR (a AND c) XOR (b AND c)
#        T2  = S0 + maj
#        h,g,f,e,d,c,b,a = g,f,e, d+T1, c,b,a, T1+T2
#   Starting values H0 = first 32 bits of the fractional part of the
#   square roots of the first 8 primes; K = cube roots of the first 64 primes.
#   SHA-256 is SECURE - used in TLS, Bitcoin, digital signatures.
# ==============================================================

MASK32 = 0xFFFFFFFF


# ---------- build the constants the way the standard defines them ----------
def iroot(n, k):                            # integer k-th root (Newton's method)
    if n < 2:
        return n
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y


def primes(count):                          # first `count` prime numbers
    found, n = [], 2
    while len(found) < count:
        if all(n % p for p in found if p * p <= n):
            found.append(n)
        n += 1
    return found


def frac_root_bits(p, k, bits):             # first `bits` bits of the fraction of p^(1/k)
    return iroot(p << (k * bits), k) & ((1 << bits) - 1)


P = primes(64)
H0 = [frac_root_bits(p, 2, 32) for p in P[:8]]         # square roots of 8 primes
K = [frac_root_bits(p, 3, 32) for p in P[:64]]         # cube roots of 64 primes


# ---------- SHA-256 ----------
def ror(x, n):                              # rotate 32-bit x right by n
    return ((x >> n) | (x << (32 - n))) & MASK32


def pad(message):
    bit_length = len(message) * 8
    message = message + b"\x80"
    while len(message) % 64 != 56:
        message = message + b"\x00"
    return message + bit_length.to_bytes(8, "big")


def compress(state, block):
    W = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):                             # message schedule
        s0 = ror(W[t - 15], 7) ^ ror(W[t - 15], 18) ^ (W[t - 15] >> 3)
        s1 = ror(W[t - 2], 17) ^ ror(W[t - 2], 19) ^ (W[t - 2] >> 10)
        W.append((W[t - 16] + s0 + W[t - 7] + s1) & MASK32)

    a, b, c, d, e, f, g, h = state
    for t in range(64):                                 # 64 rounds
        S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
        ch = (e & f) ^ (~e & g)
        T1 = (h + S1 + ch + K[t] + W[t]) & MASK32
        S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        T2 = (S0 + maj) & MASK32
        h, g, f, e = g, f, e, (d + T1) & MASK32
        d, c, b, a = c, b, a, (T1 + T2) & MASK32
    return [(x + y) & MASK32 for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def sha256(message):
    state = list(H0)
    data = pad(message)
    for i in range(0, len(data), 64):
        state = compress(state, data[i:i + 64])
    return b"".join(s.to_bytes(4, "big") for s in state).hex()


if __name__ == "__main__":
    import hashlib
    print("sha256('abc') =", sha256(b"abc"))
    # ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    ok = all(sha256(m) == hashlib.sha256(m).hexdigest() for m in [b"", b"abc", b"x" * 1000])
    print("matches hashlib:", ok)
