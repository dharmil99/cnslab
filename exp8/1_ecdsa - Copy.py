# ==============================================================
# EXPERIMENT 8 : ECDSA - SIMPLEST VERSION (no crypto library)
# ==============================================================
# Uses the small curve from Exp 3 so everything can be done by hand:
#   y^2 = x^3 + 2x + 2 (mod 17),  G = (5, 1),  n = 19 (order of G)
#
# KEYGEN : d = random (private),  Q = d*G (public)
# SIGN   : z = hash(m) mod n,  random k
#          r = (k*G).x mod n
#          s = k^-1 * (z + r*d) mod n          signature = (r, s)
# VERIFY : w = s^-1 mod n,  u1 = z*w,  u2 = r*w   (mod n)
#          X = u1*G + u2*Q    -> valid if X.x mod n == r
#
# HAND EXAMPLE: d = 7 -> Q = 7G = (0, 6)
#   m = "Transfer Rs.5000 to Account 1234" -> z = SHA-256 mod 19 = 11
#   k = 3 -> 3G = (10, 6) -> r = 10
#   s = 3^-1 * (11 + 10*7) mod 19 = 13 * 81 mod 19 = 8   -> signature (10, 8)
#   verify: w = 8^-1 = 12, u1 = 11*12 mod 19 = 18, u2 = 10*12 mod 19 = 6
#           18G + 6Q = 3G = (10, 6) -> x = 10 = r -> VALID
#
# (Real ECDSA uses the 256-bit curve P-256; with n = 19 there is a
#  1-in-19 chance two messages share a hash - fine for learning.)
# ==============================================================

import hashlib
import random

p, a, G, n = 17, 2, (5, 1), 19


def inv(v, m):                          # inverse mod m: try every number
    v = v % m
    for x in range(1, m):
        if (v * x) % m == 1:
            return x


def point_add(P, Q):                    # same as Exp 3 (None = infinity)
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        s = (3 * x1 * x1 + a) * inv(2 * y1, p) % p
    else:
        s = (y2 - y1) * inv(x2 - x1, p) % p
    x3 = (s * s - x1 - x2) % p
    return (x3, (s * (x1 - x3) - y1) % p)


def scalar_mult(k, P):                  # k*P = P + P + ... (k times)
    R = None
    for i in range(k):
        R = point_add(R, P)
    return R


def hash_mod_n(message):                # SHA-256 of the message, made smaller than n
    return int(hashlib.sha256(message.encode()).hexdigest(), 16) % n


def keygen():
    d = random.randint(1, n - 1)        # private key
    return d, scalar_mult(d, G)         # public key Q = d*G


def sign(d, message):
    z = hash_mod_n(message)
    while True:
        k = random.randint(1, n - 1)            # new random k every time
        r = scalar_mult(k, G)[0] % n            # x of k*G
        s = inv(k, n) * (z + r * d) % n
        if r != 0 and s != 0:                   # retry if either is 0
            return (r, s)


def verify(Q, message, signature):
    r, s = signature
    z = hash_mod_n(message)
    w = inv(s, n)
    u1 = z * w % n
    u2 = r * w % n
    X = point_add(scalar_mult(u1, G), scalar_mult(u2, Q))
    return X is not None and X[0] % n == r


if __name__ == "__main__":
    M = "Transfer Rs.5000 to Account 1234"

    # hand example from the top
    Q7 = scalar_mult(7, G)
    print("Q = 7G =", Q7)                                       # (0, 6)
    print("hand signature (10, 8) valid:", verify(Q7, M, (10, 8)))   # True

    # random keys
    d, Q = keygen()
    sig = sign(d, M)
    print("\nd =", d, " Q =", Q, " signature =", sig)
    print("verify original :", verify(Q, M, sig))                              # True
    print("verify tampered :", verify(Q, "Transfer Rs.9000 to Account 1234", sig))   # False
