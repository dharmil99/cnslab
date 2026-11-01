# ==============================================================
# EXPERIMENT 2 : MONOALPHABETIC SUBSTITUTION CIPHER
# ==============================================================
# THEORY:
#   Every letter is replaced by a FIXED other letter.
#   Key = a shuffled alphabet (here: keyboard order, easy to remember)
#       Plain : ABCDEFGHIJKLMNOPQRSTUVWXYZ
#       Key   : QWERTYUIOPASDFGHJKLZXCVBNM
#   So A->Q, B->W, C->E ...
#   Key space 26! but broken by FREQUENCY ANALYSIS
#   (same plain letter always gives the same cipher letter).
#   Example: HELLO -> ITSSG
# ==============================================================

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def mono_encrypt(text, key):
    result = ""
    for ch in text.upper():
        if ch.isalpha():
            pos = ALPHABET.index(ch)        # where is the letter in A..Z?
            result = result + key[pos]      # same position in the key
        else:
            result = result + ch
    return result


def mono_decrypt(text, key):
    result = ""
    for ch in text.upper():
        if ch.isalpha():
            pos = key.index(ch)             # where is the letter in the KEY?
            result = result + ALPHABET[pos] # same position in A..Z
        else:
            result = result + ch
    return result


if __name__ == "__main__":
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"
    c = mono_encrypt("HELLO WORLD", key)
    print(c)                                # ITSSG VGKSR
    print(mono_decrypt(c, key))             # HELLO WORLD
