# ==============================================================
# EXPERIMENT 1 : FERMAT PRIMALITY TEST
# ==============================================================
# THEORY:
#   Fermat's Little Theorem: if n is prime and gcd(a, n) = 1, then
#        a^(n-1) mod n = 1
#   Pick a few random bases a:
#     - answer NOT 1 for any base  -> n is COMPOSITE (100% sure)
#     - answer is 1 for all bases  -> n is PROBABLY PRIME
#   Weakness: Carmichael numbers (561, 1105, 1729) are composite but
#   give 1 for every base with gcd(a, n) = 1 -> Fermat says "prime".
# ==============================================================

import math         # for math.gcd()
import random       # for random.randint()


def fermat_test(n, k=5):
    if n < 2:                               # 0 and 1 are not prime
        return "composite"
    if n == 2 or n == 3:                    # small primes
        return "prime"
    if n % 2 == 0:                          # even numbers above 2
        return "composite"

    for i in range(k):                      # try k random bases
        a = random.randint(2, n - 2)        # random base between 2 and n-2
        while math.gcd(a, n) != 1:          # base must share no factor with n
            a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:           # a^(n-1) mod n  (a prime always gives 1)
            return "composite"
    return "prime"                          # passed every base -> probably prime


if __name__ == "__main__":
    for n in [13, 97, 7919, 15, 91, 561, 1105, 1729]:
        print(n, "->", fermat_test(n))
    # 561, 1105, 1729 are Carmichael numbers -> Fermat wrongly says "prime"
