# ==============================================================
# EXPERIMENT 1 : MILLER-RABIN PRIMALITY TEST
# ==============================================================
# THEORY:
#   Step 1: write n-1 = 2^r * d  (d odd)    e.g. 560 = 2^4 * 35
#   Step 2: for each random base a:
#             x = a^d mod n
#             if x == 1 or x == n-1          -> base passes
#             else square x up to r-1 times:
#                 if x becomes n-1           -> base passes
#             if it never becomes n-1        -> n is COMPOSITE
#   Catches Carmichael numbers too. Error <= (1/4)^k for k bases.
#   Used in RSA to check big primes.
# ==============================================================

import random


def miller_rabin(n, k=5):
    if n < 2:
        return "composite"
    if n == 2 or n == 3:
        return "prime"
    if n % 2 == 0:
        return "composite"

    # STEP 1 : n-1 = 2^r * d
    d = n - 1
    r = 0
    while d % 2 == 0:                   # keep halving while d is even
        d = d // 2
        r = r + 1

    # STEP 2 : test k random bases
    for i in range(k):
        a = random.randint(2, n - 2)    # random base
        x = pow(a, d, n)                # x = a^d mod n

        if x == 1 or x == n - 1:        # already 1 or -1
            continue                    # this base passes

        found = False
        for j in range(r - 1):          # square up to r-1 times
            x = (x * x) % n
            if x == n - 1:              # reached -1
                found = True
                break

        if found == False:              # never reached -1
            return "composite"
    return "prime"


if __name__ == "__main__":
    for n in [13, 97, 7919, 15, 91, 561, 1105, 1729]:
        print(n, "->", miller_rabin(n))
    # 561, 1105, 1729 (Carmichael) -> correctly "composite"
