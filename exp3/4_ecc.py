# ==============================================================
# EXPERIMENT 3 : ELLIPTIC CURVE CRYPTOGRAPHY (ECC)
# ==============================================================
# THEORY:
#   Curve: y^2 = x^3 + a*x + b (mod p).  "Point at infinity" O = None.
#   POINT ADDITION (P != Q):  s = (y2 - y1) / (x2 - x1)
#   POINT DOUBLING (P == Q):  s = (3*x1^2 + a) / (2*y1)
#   then  x3 = s^2 - x1 - x2,   y3 = s*(x1 - x3) - y1   (all mod p)
#   "Divide" = multiply by the inverse mod p.
#   k*G = G + G + ... + G (k times)
#   Keys: private d (number), public Q = d*G (point)
#   ECDH: shared point = d_A * Q_B = d_B * Q_A
#   Security: Elliptic Curve Discrete Log -> small keys
#             (256-bit ECC ~ 3072-bit RSA).
#
#   Example: y^2 = x^3 + 2x + 2 (mod 17), G = (5, 1) -> 2G = (6, 3)
# ==============================================================


def inv(v, p):
    v = v % p                           # make v positive
    for x in range(1, p):               # try every number
        if (v * x) % p == 1:
            return x


def is_on_curve(P, a, b, p):
    if P is None:                       # point at infinity
        return True
    x, y = P
    return (y * y - (x * x * x + a * x + b)) % p == 0


def point_add(P, Q, a, p):
    if P is None:                       # O + Q = Q
        return Q
    if Q is None:                       # P + O = P
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: # P + (-P) = O
        return None
    if P == Q:                          # doubling: tangent slope
        s = (3 * x1 * x1 + a) * inv(2 * y1, p) % p
    else:                               # addition: line slope
        s = (y2 - y1) * inv(x2 - x1, p) % p
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mult(k, P, a, p):
    R = None                            # start at O ("zero")
    for i in range(k):                  # add P, k times
        R = point_add(R, P, a, p)
    return R


def point_order(G, a, p):
    Q = G
    n = 1
    while Q is not None:                # add G until we reach O
        Q = point_add(Q, G, a, p)
        n = n + 1
    return n


if __name__ == "__main__":
    a, b, p, G = 2, 2, 17, (5, 1)
    print("2G =", point_add(G, G, a, p))                # (6, 3)
    print("order of G =", point_order(G, a, p))         # 19
    d_A, d_B = 3, 7                                     # private keys
    Q_A = scalar_mult(d_A, G, a, p)                     # (10, 6)
    Q_B = scalar_mult(d_B, G, a, p)                     # (0, 6)
    print("Q_A =", Q_A, " Q_B =", Q_B)
    print("shared:", scalar_mult(d_A, Q_B, a, p), scalar_mult(d_B, Q_A, a, p))   # both (6, 3)
