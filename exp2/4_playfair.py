# ==============================================================
# EXPERIMENT 2 : PLAYFAIR CIPHER
# ==============================================================
# THEORY:
#   1. 5x5 grid: keyword letters first (no repeats), then the rest
#      of the alphabet. I and J share one box (no J).
#      Keyword MONARCHY ->   M O N A R
#                            C H Y B D
#                            E F G I K
#                            L P Q S T
#                            U V W X Z
#   2. Split the message into pairs:
#      J -> I, same two letters -> put X between, odd length -> add X
#   3. For each pair:
#      SAME ROW    -> letter to the RIGHT  (decrypt: LEFT)
#      SAME COLUMN -> letter BELOW         (decrypt: ABOVE)
#      RECTANGLE   -> swap columns (same for decrypt)
#   Example: INSTRUMENTS -> GATLMZCLRQXA
# ==============================================================


def create_matrix(keyword):
    keyword = keyword.upper().replace("J", "I")
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"      # 25 letters, no J
    letters = ""
    for ch in keyword + alphabet:               # keyword first, then alphabet
        if ch not in letters:                   # skip repeats
            letters = letters + ch
    matrix = []
    for i in range(0, 25, 5):                   # 5 rows of 5
        matrix.append(list(letters[i:i + 5]))
    return matrix


def find_position(matrix, ch):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == ch:
                return r, c                     # row and column


def prepare_text(text):
    clean = ""
    for ch in text.upper():
        if ch.isalpha():                        # letters only
            clean = clean + ch
    clean = clean.replace("J", "I")

    pairs = []
    i = 0
    while i < len(clean):
        a = clean[i]
        if i + 1 < len(clean):
            b = clean[i + 1]
        else:
            b = "X"                             # odd length -> pad with X
        if a == b:                              # double letter -> split with X
            pairs.append(a + "X")
            i = i + 1
        else:
            pairs.append(a + b)
            i = i + 2
    return pairs


def playfair_encrypt(text, matrix):
    result = ""
    for pair in prepare_text(text):
        r1, c1 = find_position(matrix, pair[0])
        r2, c2 = find_position(matrix, pair[1])
        if r1 == r2:                            # same row -> right
            result += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:                          # same column -> down
            result += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
        else:                                   # rectangle -> swap columns
            result += matrix[r1][c2] + matrix[r2][c1]
    return result


def playfair_decrypt(text, matrix):
    result = ""
    for i in range(0, len(text), 2):            # 2 letters at a time
        r1, c1 = find_position(matrix, text[i])
        r2, c2 = find_position(matrix, text[i + 1])
        if r1 == r2:                            # same row -> left
            result += matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5]
        elif c1 == c2:                          # same column -> up
            result += matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2]
        else:
            result += matrix[r1][c2] + matrix[r2][c1]
    return result


if __name__ == "__main__":
    matrix = create_matrix("MONARCHY")
    for row in matrix:
        print(" ".join(row))
    c = playfair_encrypt("INSTRUMENTS", matrix)
    print(prepare_text("INSTRUMENTS"))          # ['IN', 'ST', 'RU', 'ME', 'NT', 'SX']
    print(c)                                    # GATLMZCLRQXA
    print(playfair_decrypt(c, matrix))          # INSTRUMENTSX
