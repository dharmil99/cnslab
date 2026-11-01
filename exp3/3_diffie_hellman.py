# ==============================================================
# EXPERIMENT 3 : DIFFIE-HELLMAN KEY EXCHANGE
# ==============================================================
# THEORY:
#   Public : prime p, generator g
#   Alice  : secret a, sends A = g^a mod p
#   Bob    : secret b, sends B = g^b mod p
#   Alice  : K = B^a mod p        Bob : K = A^b mod p
#   Same key because (g^b)^a = g^(ab) = (g^a)^b
#   It does NOT encrypt a message - it only creates a shared key,
#   which is then used by a symmetric cipher (e.g. AES).
#   Weakness: man-in-the-middle (no authentication).
#
#   Example: p=23, g=5, a=6, b=15 -> A=8, B=19, key=2
# ==============================================================


def diffie_hellman(p, g, a, b):
    A = pow(g, a, p)            # Alice's public value
    B = pow(g, b, p)            # Bob's public value
    K_A = pow(B, a, p)          # Alice's key (uses her secret a)
    K_B = pow(A, b, p)          # Bob's key (uses his secret b)
    return A, B, K_A, K_B


if __name__ == "__main__":
    A, B, K_A, K_B = diffie_hellman(23, 5, 6, 15)
    print("A =", A, " B =", B)                                  # 8, 19
    print("K_A =", K_A, " K_B =", K_B, " match:", K_A == K_B)   # 2, 2
