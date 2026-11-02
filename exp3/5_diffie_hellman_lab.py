# ==============================================================
# EXPERIMENT 3 : DIFFIE-HELLMAN - LAB VERSION
#                (random 4-digit prime, its generator, 100 exchanges)
# ==============================================================
# THEORY:
#   1. Pick a prime p (here 4 digits: 1000-9999).
#   2. Find a generator g (primitive root) of p:
#      the powers g^1, g^2, ..., g^(p-1) mod p give every number 1..p-1.
#   3. For every exchange:
#        Alice : secret a,  A = g^a mod p   (sent to Bob)
#        Bob   : secret b,  B = g^b mod p   (sent to Alice)
#        Alice : K_A = B^a mod p
#        Bob   : K_B = A^b mod p
#        K_A == K_B  because (g^b)^a = g^(ab) = (g^a)^b
#   p and g are generated ONCE and shared; a, b are new for every exchange.
# ==============================================================

import random


def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:                   # check divisors up to sqrt(n)
        if n % i == 0:
            return False
        i += 1
    return True


def random_prime(low, high):
    while True:
        n = random.randint(low, high)   # random number in the range
        if is_prime(n):
            return n


def primitive_root(p):
    for g in range(2, p):               # try g = 2, 3, 4, ...
        values = set()
        x = 1
        for i in range(1, p):
            x = (x * g) % p             # g^1, g^2, ... mod p
            values.add(x)
        if len(values) == p - 1:        # got every number 1..p-1
            return g


def diffie_hellman(p, g, a, b):
    A = pow(g, a, p)                    # Alice's public value
    B = pow(g, b, p)                    # Bob's public value
    K_A = pow(B, a, p)                  # Alice's shared secret
    K_B = pow(A, b, p)                  # Bob's shared secret
    return A, B, K_A, K_B


if __name__ == "__main__":
    p = random_prime(1000, 9999)        # common prime (generated once)
    g = primitive_root(p)               # common generator
    print("Common prime     p =", p)
    print("Common generator g =", g)
    print()
    print(f"{'#':>3} | {'a':>5} {'A':>5} | {'b':>5} {'B':>5} | {'K_A':>5} {'K_B':>5} | match")
    print("-" * 52)

    matches = 0
    for row in range(1, 101):           # 100 independent exchanges
        a = random.randint(2, p - 2)    # Alice's private value
        b = random.randint(2, p - 2)    # Bob's private value
        A, B, K_A, K_B = diffie_hellman(p, g, a, b)
        if K_A == K_B:
            matches += 1
        if row <= 10:                   # show the first 10 rows
            print(f"{row:>3} | {a:>5} {A:>5} | {b:>5} {B:>5} | {K_A:>5} {K_B:>5} | {'Yes' if K_A == K_B else 'No'}")

    print("...")
    print(f"Shared secrets matched: {matches}/100")
