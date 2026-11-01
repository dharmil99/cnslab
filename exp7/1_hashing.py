# ==============================================================
# EXPERIMENT 7 : HASHING (MD5, SHA-1, SHA-256, SHA-512)
# ==============================================================
# THEORY:
#   A hash function turns ANY input into a FIXED-size output (digest).
#     MD5 = 128 bits, SHA-1 = 160 bits, SHA-256 = 256 bits, SHA-512 = 512 bits
#   Properties:
#     - one-way         : cannot get the message back from the hash
#     - collision-resistant : hard to find two messages with the same hash
#     - avalanche effect: change 1 character -> about HALF the bits change
#   Uses: integrity check of files/messages, password storage, signatures.
#   MD5 and SHA-1 are BROKEN (collisions found) -> use SHA-256 or above.
#   A hash has NO key -> anyone can recompute it (that's why we need HMAC).
# ==============================================================

import hashlib


# --------------------------------------------------------------
# hash_text : hash a string with the chosen algorithm
# --------------------------------------------------------------
def hash_text(text, algorithm="sha256"):
    data = text.encode()                        # text -> bytes (hash works on bytes)
    return hashlib.new(algorithm, data).hexdigest()   # digest as hex characters


# --------------------------------------------------------------
# bits_changed : how many bits differ between two hashes (avalanche)
# --------------------------------------------------------------
def bits_changed(hash1, hash2):
    x = int(hash1, 16) ^ int(hash2, 16)         # hex -> number; XOR gives 1 where bits differ
    return bin(x).count("1")                    # count the 1s


# --------------------------------------------------------------
# hash_file : SHA-256 of a whole file (integrity check)
# --------------------------------------------------------------
def hash_file(path):
    with open(path, "rb") as f:                 # "rb" = read as bytes
        data = f.read()
    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":
    msg = "Hello World"

    # 1) same message, different algorithms
    for alg in ["md5", "sha1", "sha256", "sha512"]:
        h = hash_text(msg, alg)
        print(f"{alg:7} {len(h) * 4:3} bits  {h}")     # 1 hex char = 4 bits

    # 2) avalanche effect: change one letter
    h1 = hash_text("Hello World")
    h2 = hash_text("Hello Worle")
    print("\n" + h1 + "\n" + h2)
    print("bits changed:", bits_changed(h1, h2), "out of 256")   # about 128

    # 3) file integrity: hash before and after a change
    with open("sample.txt", "w") as f:
        f.write("Transfer Rs.5000 to Account 1234")
    before = hash_file("sample.txt")
    with open("sample.txt", "w") as f:
        f.write("Transfer Rs.9000 to Account 1234")      # file tampered
    after = hash_file("sample.txt")
    print("\nfile unchanged?", before == after)          # False -> tampering detected
