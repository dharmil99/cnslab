# ==============================================================
# EXPERIMENT 1 (extra) : MODULAR POWER WITHOUT pow()
#                        (square-and-multiply)
# ==============================================================
# THEORY:
#   Use this if the examiner says "don't use pow(a, b, n)".
#   Look at the exponent b in binary, from the right:
#     - if the bit is 1 -> multiply the answer by a
#     - always square a, then move to the next bit (b // 2)
#   e.g. 3^13 : 13 = 1101 -> 3^8 * 3^4 * 3^1
#
#   SIMPLEST version (slow, fine for small b):
#     result = 1
#     for i in range(b): result = (result * a) % n
# ==============================================================


def mod_pow(a, b, n):
    result = 1                          # start with 1
    a = a % n                           # make a smaller first
    while b > 0:                        # until no bits are left
        if b % 2 == 1:                  # lowest bit is 1
            result = (result * a) % n   # multiply it in
        a = (a * a) % n                 # square a
        b = b // 2                      # next bit
    return result


def mod_pow_simple(a, b, n):
    result = 1
    for i in range(b):                  # multiply by a, b times
        result = (result * a) % n
    return result


if __name__ == "__main__":
    print(mod_pow(3, 13, 7), mod_pow_simple(3, 13, 7), pow(3, 13, 7))   # all 3
    print(mod_pow(2, 560, 561), pow(2, 560, 561))                       # both 1
