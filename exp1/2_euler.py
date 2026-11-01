# ==============================================================
# EXPERIMENT 1 : EULER PRIMALITY TEST
# ==============================================================
# THEORY:
#   Euler's Criterion: if n is an odd prime and gcd(a, n) = 1, then
#        a^((n-1)/2) mod n  =  1  or  n-1      (n-1 means -1 in mod n)
#   - answer is anything else -> n is COMPOSITE (100% sure)
#   - answer is 1 or n-1      -> n is PROBABLY PRIME
#   Stricter than Fermat, so it catches more composites.
#   NOTE: pow() never gives -1, it gives n-1. So check "x != n-1",
#         NOT "abs(x) != 1".
# ==============================================================

import math
import random


def euler_test(n, k=5):
    if n < 2:
        return "composite"
    if n == 2 or n == 3:
        return "prime"
    if n % 2 == 0:
        return "composite"

    for i in range(k):                      # try k random bases
        a = random.randint(2, n - 2)
        while math.gcd(a, n) != 1:          # base must share no factor with n
            a = random.randint(2, n - 2)
        x = pow(a, (n - 1) // 2, n)         # a^((n-1)/2) mod n   (// = whole-number division)
        if x != 1 and x != n - 1:           # prime must give 1 or -1 (= n-1)
            return "composite"
    return "prime"


if __name__ == "__main__":
    for n in [13, 97, 7919, 15, 91, 561, 1105, 1729]:
        print(n, "->", euler_test(n))
