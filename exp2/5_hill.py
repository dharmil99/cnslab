# ==============================================================
# EXPERIMENT 2 : HILL CIPHER (2 x 2)
# ==============================================================
# THEORY:
#   Take 2 letters [p1, p2] and multiply by the key matrix (mod 26).
#        K = | a b |      c1 = (a*p1 + b*p2) mod 26
#            | c d |      c2 = (c*p1 + d*p2) mod 26
#   Decrypt with the INVERSE matrix:
#        det = (a*d - b*c) mod 26,   det_inv = number with det*det_inv % 26 = 1
#        K^-1 = det_inv * |  d -b |   (mod 26)
#                         | -c  a |
#   Key is valid only if gcd(det, 26) = 1.
#   Example: K = |3 3|, det = 9, det_inv = 3
#                |2 5|
#            HELP -> HIAT
# ==============================================================


def mod_inverse(a):
    a = a % 26
    for x in range(1, 26):                  # try every number
        if (a * x) % 26 == 1:
            return x
    return None                             # no inverse -> bad key


def prepare_text(text):
    clean = ""
    for ch in text.upper():
        if ch.isalpha():                    # letters only
            clean = clean + ch
    if len(clean) % 2 != 0:                 # odd length -> add X
        clean = clean + "X"
    return clean


def hill_encrypt(text, key):
    text = prepare_text(text)
    result = ""
    for i in range(0, len(text), 2):        # 2 letters at a time
        p1 = ord(text[i]) - 65
        p2 = ord(text[i + 1]) - 65
        c1 = (key[0][0] * p1 + key[0][1] * p2) % 26     # top row x pair
        c2 = (key[1][0] * p1 + key[1][1] * p2) % 26     # bottom row x pair
        result = result + chr(c1 + 65) + chr(c2 + 65)
    return result


def inverse_key(key):
    a, b = key[0][0], key[0][1]
    c, d = key[1][0], key[1][1]
    det = (a * d - b * c) % 26
    det_inv = mod_inverse(det)
    return [[(d * det_inv) % 26, (-b * det_inv) % 26],      # swap a and d,
            [(-c * det_inv) % 26, (a * det_inv) % 26]]      # negate b and c


def hill_decrypt(text, key):
    return hill_encrypt(text, inverse_key(key))     # multiply by K^-1


if __name__ == "__main__":
    key = [[3, 3], [2, 5]]
    print("inverse key:", inverse_key(key))     # [[15, 17], [20, 9]]
    c = hill_encrypt("HELP", key)
    print(c)                                    # HIAT
    print(hill_decrypt(c, key))                 # HELP
