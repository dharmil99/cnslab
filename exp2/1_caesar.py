# ==============================================================
# EXPERIMENT 2 : CAESAR CIPHER
# ==============================================================
# THEORY:
#   Shift every letter by a fixed key.   A=0, B=1, ... Z=25
#   Encrypt : C = (P + key) mod 26
#   Decrypt : P = (C - key) mod 26
#   Only 25 keys -> broken by trying all (brute force).
#   Example (key 3): HELLO -> KHOOR
# ==============================================================


def caesar_encrypt(text, key):
    result = ""
    for ch in text.upper():                 # each character, in capitals
        if ch.isalpha():                    # only letters change
            num = ord(ch) - 65              # letter -> number (A=0)
            num = (num + key) % 26          # shift forward, wrap after Z
            result = result + chr(num + 65) # number -> letter
        else:
            result = result + ch            # spaces stay the same
    return result


def caesar_decrypt(text, key):
    result = ""
    for ch in text.upper():
        if ch.isalpha():
            num = ord(ch) - 65
            num = (num - key) % 26          # shift BACK
            result = result + chr(num + 65)
        else:
            result = result + ch
    return result


if __name__ == "__main__":
    key = 3
    c = caesar_encrypt("HELLO WORLD", key)
    print(c)                                # KHOOR ZRUOG
    print(caesar_decrypt(c, key))           # HELLO WORLD
