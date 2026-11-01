# ==============================================================
# EXPERIMENT 2 : VIGENERE CIPHER
# ==============================================================
# THEORY:
#   Caesar with a DIFFERENT shift for each letter, taken from a
#   keyword that repeats.  (A=0 ... Z=25)
#   Encrypt : C_i = (P_i + K_i) mod 26
#   Decrypt : P_i = (C_i - K_i) mod 26
#   Polyalphabetic -> hides frequencies better than Caesar.
#   Example (key LEMON): ATTACK AT DAWN -> LXFOPV EF RNHR
# ==============================================================


def vigenere_encrypt(text, key):
    result = ""
    j = 0                                       # which key letter to use next
    for ch in text.upper():
        if ch.isalpha():
            p = ord(ch) - 65                    # plaintext letter -> number
            k = ord(key[j % len(key)]) - 65     # key letter -> number (key repeats)
            result = result + chr((p + k) % 26 + 65)
            j = j + 1                           # next key letter (spaces don't use one)
        else:
            result = result + ch
    return result


def vigenere_decrypt(text, key):
    result = ""
    j = 0
    for ch in text.upper():
        if ch.isalpha():
            c = ord(ch) - 65
            k = ord(key[j % len(key)]) - 65
            result = result + chr((c - k) % 26 + 65)    # SUBTRACT the key
            j = j + 1
        else:
            result = result + ch
    return result


if __name__ == "__main__":
    key = "LEMON"
    c = vigenere_encrypt("ATTACK AT DAWN", key)
    print(c)                                # LXFOPV EF RNHR
    print(vigenere_decrypt(c, key))         # ATTACK AT DAWN
