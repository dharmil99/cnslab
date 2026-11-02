
# CHINESE REMAINDER THEOREM (CRT)
# THEORY:
#
# CRT is used to find a number x satisfying multiple
# simultaneous congruences:
#
#     x ≡ a1 (mod m1)
#     x ≡ a2 (mod m2)
#     ...
#     x ≡ an (mod mn)
#
# The moduli m1, m2, ..., mn must be pairwise coprime.
#
# Step 1:
# Calculate the product of all moduli:
#
#     M = m1 * m2 * ... * mn
#
# Step 2:
# For each modulus mi, calculate:
#
#     Mi = M / mi
#
# Step 3:
# Find the modular inverse of Mi:
#
#     yi = Mi^(-1) mod mi
#
# Step 4:
# Calculate the final solution:
#
#     x = (a1*M1*y1 + a2*M2*y2 + ... + an*Mn*yn) mod M
#
# The result is the unique solution modulo M.
#
# Example:
#
#     x ≡ 2 (mod 3)
#     x ≡ 3 (mod 5)
#     x ≡ 2 (mod 7)
#
# Solution:
#
#     x = 23
#
# because:
#     23 mod 3 = 2
#     23 mod 5 = 3
#     23 mod 7 = 2
#
# ============================================================


def crt(a, m):

    # Calculate M = product of all moduli
    M = 1

    for mi in m:
        M = M * mi

    # Variable to store the final sum
    x = 0

    # Calculate each CRT term
    for ai, mi in zip(a, m):

        # Calculate Mi = M / mi
        Mi = M // mi

        # Calculate modular inverse of Mi modulo mi
        yi = pow(Mi, -1, mi)

        # Add the CRT term
        x = x + ai * Mi * yi

    # Return solution modulo M
    return x % M


# Remainders
a = [2, 3, 2]

# Moduli
m = [3, 5, 7]

# Calculate CRT solution
result = crt(a, m)

print("CRT Solution:", result)