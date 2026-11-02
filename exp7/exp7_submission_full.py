# ==============================================================
# EXPERIMENT 7 : COMPARATIVE ANALYSIS OF CRYPTOGRAPHIC HASH FUNCTIONS AND MACs
# Vansh Lathiya | UID 2024300124 | B3
#
# All code from the submitted notebook Exp07_Hash_MAC_2024300124.ipynb, in one file.
# MD5, SHA-1, SHA-256, SHA-512 and HMAC are implemented FROM SCRATCH
# (hashlib / hmac are only used inside self_test() to check the results).
#
# Run:  python3 exp7_submission_full.py
# Needs: pip install pandas matplotlib openpyxl
#        and Hash_and_MAC_Database.xlsx (the lab dataset) in the same folder.
# Output: 2024300124_VanshLathiya_Hash_MAC.xlsx and graphs/graph1..4.png
# ==============================================================


# --------------------------------------------------------------
# Experiment 7 – Comparative Analysis of Cryptographic Hash Functions and MACs
#
# **Vansh Lathiya** | UID 2024300124 | Class/Batch B3 | CNS Lab
#
# MD5, SHA-1, SHA-256, SHA-512 and HMAC are implemented from scratch (no `hashlib` / `hmac`).
# Run all cells top to bottom with `Hash_and_MAC_Database.xlsx` in the same folder; the last
# export cell writes the completed workbook and the four graphs.
# --------------------------------------------------------------

import math
import os
from copy import copy

import matplotlib.pyplot as plt
import pandas as pd
try:
    from IPython.display import Image, display
except ImportError:          # running outside Jupyter
    display = print
    Image = lambda path, width=None: path
from openpyxl import load_workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side

STUDENT_NAME = "Vansh Lathiya"
UID = "2024300124"
CLASS_DIV = "B3"
KEY_SUFFIX = "CNS-HMAC-KEY"

INPUT_XLSX = "Hash_and_MAC_Database.xlsx"
OUTPUT_XLSX = f"{UID}_VanshLathiya_Hash_MAC.xlsx"
GRAPHS_DIR = "graphs"

pd.set_option("display.max_colwidth", 48)
pd.set_option("display.width", 200)

# --------------------------------------------------------------
# 1. Algorithms (from scratch)
#
# Helpers and round constants, derived the way the standards define them.
# --------------------------------------------------------------

MASK32 = (1 << 32) - 1
MASK64 = (1 << 64) - 1


def rol(x, n, bits=32):
    """Rotate left."""
    return ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)


def ror(x, n, bits=32):
    """Rotate right."""
    return ((x >> n) | (x << (bits - n))) & ((1 << bits) - 1)


def iroot(n, k):
    """Integer k-th root (Newton's method)."""
    if n < 2:
        return n
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y


def primes(count):
    found, n = [], 2
    while len(found) < count:
        if all(n % p for p in found if p * p <= n):
            found.append(n)
        n += 1
    return found


def frac_root_bits(p, k, bits):
    """First `bits` bits of the fractional part of p^(1/k)."""
    return iroot(p << (k * bits), k) & ((1 << bits) - 1)


_P = primes(80)

MD5_K = [int(abs(math.sin(i + 1)) * 2 ** 32) & MASK32 for i in range(64)]
MD5_SHIFTS = ([7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 +
              [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4)

SHA1_K = [iroot(n << 60, 2) for n in (2, 3, 5, 10)]                # 2^30 * sqrt(n)

SHA256_H0 = [frac_root_bits(p, 2, 32) for p in _P[:8]]              # sqrt of primes
SHA256_K = [frac_root_bits(p, 3, 32) for p in _P[:64]]              # cbrt of primes
SHA512_H0 = [frac_root_bits(p, 2, 64) for p in _P[:8]]
SHA512_K = [frac_root_bits(p, 3, 64) for p in _P[:80]]

# --------------------------------------------------------------
# Merkle–Damgård base class
# All four hashes share padding and block processing; each algorithm only defines its initial state and compression function.
# --------------------------------------------------------------

class MerkleDamgardHash:
    """Pad -> split into blocks -> compress each block -> output state."""
    name = ""
    block_size = 64      # bytes
    digest_size = 16     # bytes
    word_size = 4        # bytes
    length_field = 8     # bytes holding the bit-length
    endian = "big"

    def initial_state(self):
        raise NotImplementedError

    def compress(self, state, block):
        raise NotImplementedError

    def pad(self, message: bytes) -> bytes:
        """Append 0x80, zeros, then the message length in bits."""
        bit_length = (len(message) * 8) & ((1 << (8 * self.length_field)) - 1)
        padded = message + b"\x80"
        while (len(padded) + self.length_field) % self.block_size:
            padded += b"\x00"
        return padded + bit_length.to_bytes(self.length_field, self.endian)

    def words(self, block):
        w = self.word_size
        return [int.from_bytes(block[i:i + w], self.endian) for i in range(0, len(block), w)]

    def digest(self, message: bytes) -> bytes:
        state = self.initial_state()
        data = self.pad(message)
        for i in range(0, len(data), self.block_size):
            state = self.compress(state, data[i:i + self.block_size])
        out = b"".join(s.to_bytes(self.word_size, self.endian) for s in state)
        return out[:self.digest_size]

    def hexdigest(self, message: bytes) -> str:
        return self.digest(message).hex()

# --------------------------------------------------------------
# MD5 (RFC 1321)
# --------------------------------------------------------------

class MD5(MerkleDamgardHash):
    name, block_size, digest_size, word_size, endian = "md5", 64, 16, 4, "little"

    def initial_state(self):
        return [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def compress(self, state, block):
        M = self.words(block)
        a, b, c, d = state
        for i in range(64):
            rnd = i // 16                                       # 4 rounds of 16 steps
            if rnd == 0:
                f, g = (b & c) | (~b & d), i
            elif rnd == 1:
                f, g = (b & d) | (c & ~d), (5 * i + 1) % 16
            elif rnd == 2:
                f, g = b ^ c ^ d, (3 * i + 5) % 16
            else:
                f, g = c ^ (b | (~d & MASK32)), (7 * i) % 16
            temp = (a + (f & MASK32) + MD5_K[i] + M[g]) & MASK32
            a, b, c, d = d, (b + rol(temp, MD5_SHIFTS[i])) & MASK32, b, c
        return [(x + y) & MASK32 for x, y in zip(state, (a, b, c, d))]

# --------------------------------------------------------------
# SHA-1 (FIPS 180-4)
# --------------------------------------------------------------

class SHA1(MerkleDamgardHash):
    name, block_size, digest_size, word_size = "sha1", 64, 20, 4

    def initial_state(self):
        return [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    def compress(self, state, block):
        W = self.words(block)
        for t in range(16, 80):                                  # expand to 80 words
            W.append(rol(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1))
        a, b, c, d, e = state
        for t in range(80):
            stage = t // 20
            if stage == 0:
                f = (b & c) ^ (~b & d)                           # Ch
            elif stage == 2:
                f = (b & c) ^ (b & d) ^ (c & d)                  # Maj
            else:
                f = b ^ c ^ d                                    # Parity
            T = (rol(a, 5) + (f & MASK32) + e + SHA1_K[stage] + W[t]) & MASK32
            a, b, c, d, e = T, a, rol(b, 30), c, d
        return [(x + y) & MASK32 for x, y in zip(state, (a, b, c, d, e))]

# --------------------------------------------------------------
# SHA-256 and SHA-512 (FIPS 180-4)
# One SHA-2 class; the two variants differ only in word size, constants, rounds and rotation amounts.
# --------------------------------------------------------------

class SHA2(MerkleDamgardHash):
    rounds = 64
    K = H0 = None
    big_sigma0 = big_sigma1 = small_sigma0 = small_sigma1 = None   # rotation amounts

    def initial_state(self):
        return list(self.H0)

    def compress(self, state, block):
        bits = self.word_size * 8
        mask = (1 << bits) - 1
        r = lambda x, n: ror(x, n, bits)
        s0a, s0b, s0c = self.small_sigma0
        s1a, s1b, s1c = self.small_sigma1
        S0a, S0b, S0c = self.big_sigma0
        S1a, S1b, S1c = self.big_sigma1

        W = self.words(block)
        for t in range(16, self.rounds):                          # message schedule
            s0 = r(W[t - 15], s0a) ^ r(W[t - 15], s0b) ^ (W[t - 15] >> s0c)
            s1 = r(W[t - 2], s1a) ^ r(W[t - 2], s1b) ^ (W[t - 2] >> s1c)
            W.append((W[t - 16] + s0 + W[t - 7] + s1) & mask)

        a, b, c, d, e, f, g, h = state
        for t in range(self.rounds):
            S1 = r(e, S1a) ^ r(e, S1b) ^ r(e, S1c)
            ch = (e & f) ^ (~e & mask & g)
            T1 = (h + S1 + ch + self.K[t] + W[t]) & mask
            S0 = r(a, S0a) ^ r(a, S0b) ^ r(a, S0c)
            maj = (a & b) ^ (a & c) ^ (b & c)
            T2 = (S0 + maj) & mask
            h, g, f, e = g, f, e, (d + T1) & mask
            d, c, b, a = c, b, a, (T1 + T2) & mask
        return [(x + y) & mask for x, y in zip(state, (a, b, c, d, e, f, g, h))]


class SHA256(SHA2):
    name, block_size, digest_size, word_size, length_field = "sha256", 64, 32, 4, 8
    rounds, K, H0 = 64, SHA256_K, SHA256_H0
    big_sigma0, big_sigma1 = (2, 13, 22), (6, 11, 25)
    small_sigma0, small_sigma1 = (7, 18, 3), (17, 19, 10)


class SHA512(SHA2):
    name, block_size, digest_size, word_size, length_field = "sha512", 128, 64, 8, 16
    rounds, K, H0 = 80, SHA512_K, SHA512_H0
    big_sigma0, big_sigma1 = (28, 34, 39), (14, 18, 41)
    small_sigma0, small_sigma1 = (1, 8, 7), (19, 61, 6)


ALGORITHMS = {"md5": MD5(), "sha1": SHA1(), "sha256": SHA256(), "sha512": SHA512()}


def hash_bytes(algo: str, message: bytes) -> bytes:
    return ALGORITHMS[algo].digest(message)

# --------------------------------------------------------------
# HMAC (RFC 2104)
# `HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))`
# --------------------------------------------------------------

ALGORITHMS = {"md5": MD5(), "sha1": SHA1(), "sha256": SHA256(), "sha512": SHA512()}


def hash_bytes(algo: str, message: bytes) -> bytes:
    return ALGORITHMS[algo].digest(message)


IPAD, OPAD = 0x36, 0x5C


def hmac_bytes(key: bytes, message: bytes, algo: str) -> bytes:
    h = ALGORITHMS[algo]
    if len(key) > h.block_size:                 # long key -> hash it
        key = h.digest(key)
    key = key.ljust(h.block_size, b"\x00")      # pad to block size
    inner = h.digest(bytes(k ^ IPAD for k in key) + message)
    return h.digest(bytes(k ^ OPAD for k in key) + inner)


def constant_time_equal(a: str, b: str) -> bool:
    """Timing-safe string comparison."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    return result == 0

# --------------------------------------------------------------
# Self-test
# Published test vectors, an RFC 4231 HMAC vector, and random cross-checks against Python's `hashlib`/`hmac` (used only here, as a reference).
# --------------------------------------------------------------

def self_test(random_cases=300, verbose=True):
    """Check against published vectors and against hashlib/hmac."""
    import hashlib
    import hmac as std_hmac
    import os
    import random

    published = {
        ("md5", b""): "d41d8cd98f00b204e9800998ecf8427e",
        ("md5", b"abc"): "900150983cd24fb0d6963f7d28e17f72",
        ("sha1", b"abc"): "a9993e364706816aba3e25717850c26c9cd0d89d",
        ("sha256", b"abc"): "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ("sha512", b"abc"): ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                             "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    }
    for (algo, msg), expected in published.items():
        assert ALGORITHMS[algo].hexdigest(msg) == expected, f"{algo} vector failed"

    # RFC 4231 test case 2
    assert hmac_bytes(b"Jefe", b"what do ya want for nothing?", "sha256").hex() == \
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

    rfc_cases = [                                # RFC 2202 / 4231 inputs
        (b"\x0b" * 20, b"Hi There"),
        (b"Jefe", b"what do ya want for nothing?"),
        (b"\xaa" * 20, b"\xdd" * 50),
        (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First"),
    ]

    rng = random.Random(7)
    lengths = list(range(0, 260)) + [rng.randint(260, 2000) for _ in range(random_cases)]
    n_hash = n_hmac = 0
    for algo in ALGORITHMS:
        for n in lengths:                        # covers all padding boundaries
            msg = os.urandom(n)
            assert hash_bytes(algo, msg) == hashlib.new(algo, msg).digest(), (algo, n)
            n_hash += 1
        for key, msg in rfc_cases:
            assert hmac_bytes(key, msg, algo) == std_hmac.new(key, msg, algo).digest(), algo
            n_hmac += 1
        for _ in range(random_cases):            # short, block-size and long keys
            key = os.urandom(rng.randint(0, 200))
            msg = os.urandom(rng.randint(0, 500))
            assert hmac_bytes(key, msg, algo) == std_hmac.new(key, msg, algo).digest(), algo
            n_hmac += 1

    if verbose:
        print(f"Self-test passed: {len(published)} published vectors, RFC 4231 HMAC vector, "
              f"{n_hash} hash + {n_hmac} HMAC checks vs hashlib/hmac.")
    return True


assert self_test(random_cases=300)

# --------------------------------------------------------------
# 2. UID-based key
# `Key = SHA-256(str(UID) + "CNS-HMAC-KEY")`, used as 32 raw bytes for all four HMACs.
# --------------------------------------------------------------

ALGOS = ["md5", "sha1", "sha256", "sha512"]
HASH_NAMES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}
HMAC_NAMES = {"md5": "HMAC-MD5", "sha1": "HMAC-SHA1", "sha256": "HMAC-SHA256", "sha512": "HMAC-SHA512"}
BITS = {"md5": 128, "sha1": 160, "sha256": 256, "sha512": 512}


def generate_key(uid: str) -> bytes:
    """K = SHA-256(str(UID) || "CNS-HMAC-KEY") -> 32-byte (256-bit) key."""
    return hash_bytes("sha256", (str(uid) + KEY_SUFFIX).encode("utf-8"))


def flip_last_bit(key: bytes) -> bytes:
    """K2 = K1 with its last bit flipped."""
    return key[:-1] + bytes([key[-1] ^ 0x01])


def hash_hex(algo: str, message: str) -> str:
    return hash_bytes(algo, message.encode("utf-8")).hex()


def hmac_hex(key: bytes, algo: str, message: str) -> str:
    return hmac_bytes(key, message.encode("utf-8"), algo).hex()


def changed_bits(hex_a: str, hex_b: str) -> int:
    """Number of differing bits (XOR, count 1s)."""
    return bin(int(hex_a, 16) ^ int(hex_b, 16)).count("1")


def verify_mac(key: bytes, algo: str, received_message: str, received_mac: str) -> bool:
    """Receiver: recompute MAC and compare."""
    return constant_time_equal(hmac_hex(key, algo, received_message), received_mac)


KEY = generate_key(UID)
print("UID        :", UID)
print("Key (hex)  :", KEY.hex())
print("Key length :", len(KEY) * 8, "bits")

# --------------------------------------------------------------
# 3. Dataset
# --------------------------------------------------------------

df_data = pd.read_excel(INPUT_XLSX, sheet_name="Dataset")
assert len(df_data) == 100
messages = list(df_data.itertuples(index=False, name=None))
print(df_data.head())

# --------------------------------------------------------------
# 4. Part A – Hash generation
# All four hashes (and, for later parts, all four HMACs) of every original and modified message.
# --------------------------------------------------------------

def run_experiment(messages, key1):
    key2 = flip_last_bit(key1)
    res = {"hash": [], "hmac": [], "hash_av": [], "hmac_av": []}

    for sr, orig, mod in messages:
        h_row, m_row = {}, {}
        for a in ALGOS:
            ho, hm = hash_hex(a, orig), hash_hex(a, mod)
            mo, mm = hmac_hex(key1, a, orig), hmac_hex(key1, a, mod)
            h_row[a], m_row[a] = (ho, hm), (mo, mm)
            res["hash_av"].append((sr, HASH_NAMES[a], ho, hm, changed_bits(ho, hm), BITS[a]))
            res["hmac_av"].append((sr, HMAC_NAMES[a], mo, mm, changed_bits(mo, mm), BITS[a]))
        res["hash"].append((sr, orig, mod, h_row))
        res["hmac"].append((sr, orig, mod, m_row))
    res["key2"] = key2
    return res


res = run_experiment(messages, KEY)

df_hash = pd.DataFrame([{"Sr_No": sr, "Original": o, "Modified": m,
                         **{f"{HASH_NAMES[a]}_Orig": row[a][0][:16] + "…" for a in ALGOS}}
                        for sr, o, m, row in res["hash"]])
print(len(res["hash"]) * 8, "hash values computed")
print(df_hash.head())

# --------------------------------------------------------------
# 5. Part B – Hash avalanche
# `Avalanche (%) = Changed Bits / Total Bits × 100`
# --------------------------------------------------------------

def summary(rows, names):
    out = {}
    for a in ALGOS:
        vals = [r[4] / r[5] * 100 for r in rows if r[1] == names[a]]
        bits = [r[4] for r in rows if r[1] == names[a]]
        out[a] = dict(avg=sum(vals) / len(vals), mn=min(vals), mx=max(vals),
                      avg_bits=sum(bits) / len(bits))
    return out


hs = summary(res["hash_av"], HASH_NAMES)
df_hash_av = pd.DataFrame([{"Algorithm": HASH_NAMES[a], "Total Bits": BITS[a],
                            "Avg Changed Bits": round(hs[a]["avg_bits"], 2),
                            "Average (%)": round(hs[a]["avg"], 3), "Minimum (%)": round(hs[a]["mn"], 3),
                            "Maximum (%)": round(hs[a]["mx"], 3)} for a in ALGOS])
print(df_hash_av)

# --------------------------------------------------------------
# 6. Part C – HMAC generation
# --------------------------------------------------------------

df_hmac = pd.DataFrame([{"Sr_No": sr, "Original": o, "Modified": m,
                         **{f"{HMAC_NAMES[a]}_Orig": row[a][0][:16] + "…" for a in ALGOS}}
                        for sr, o, m, row in res["hmac"]])
print(len(res["hmac"]) * 8, "HMAC values computed")
print(df_hmac.head())

# --------------------------------------------------------------
# 7. Part D – Hash vs HMAC
# A hash is keyless, so an attacker can change the message and simply recompute it. HMAC needs the secret key, so only key holders can produce a valid MAC.
# --------------------------------------------------------------

PART_D = [
    ("Requires secret key", "No", "Yes"),
    ("Provides integrity", "Only against accidental change (attacker can recompute it)", "Yes"),
    ("Provides authentication", "No", "Yes"),
    ("Anyone can calculate it", "Yes", "No - only holders of the key"),
    ("Can verify possession of secret key", "No", "Yes"),
    ("Detects message modification", "Accidental: Yes; malicious: No (hash can be replaced)", "Yes"),
]

print(pd.DataFrame(PART_D, columns=["Property", "Hash", "HMAC"]))

# --------------------------------------------------------------
# 8. Part E – Tampering detection (HMAC-SHA256)
# Sender sends `(M, HMAC(K, M))`; receiver recomputes the MAC on what arrived.
# --------------------------------------------------------------

rows = []
for sr, orig, mod in messages:
    sent_mac = hmac_hex(KEY, "sha256", orig)
    for mtype, received in (("Original", orig), ("Modified", mod)):
        match = verify_mac(KEY, "sha256", received, sent_mac)
        rows.append({"Sr_No": sr, "Type": mtype, "Message": received,
                     "MAC_Match": "Yes" if match else "No",
                     "Tampering_Detected": "No" if match else "Yes"})
df_tamper = pd.DataFrame(rows)
display(df_tamper.head(6))
print(pd.crosstab(df_tamper["Type"], df_tamper["Tampering_Detected"]))

# --------------------------------------------------------------
# 9. Part F – Receiver-side MAC verification
# --------------------------------------------------------------

cases = [("Transfer Rs.1000 to Account A", "Transfer Rs.1000 to Account A", "Original"),
         ("Transfer Rs.1000 to Account A", "Transfer Rs.9000 to Account A", "Modified"),
         (messages[0][1], messages[0][1], "Original"),
         (messages[0][1], messages[0][2], "Modified")]
print(pd.DataFrame([{"Case": c, "Message Received": recv,
               "Received MAC": hmac_hex(KEY, "sha256", sent)[:20] + "…",
               "Recalculated MAC": hmac_hex(KEY, "sha256", recv)[:20] + "…",
               "Verification": "PASS" if verify_mac(KEY, "sha256", recv, hmac_hex(KEY, "sha256", sent))
               else "FAIL"} for sent, recv, c in cases]))

# --------------------------------------------------------------
# 10. Part G – Key sensitivity
# Same message, K2 = K1 with its last bit flipped (1 of 256 key bits differ).
# --------------------------------------------------------------

KEY2 = res["key2"]
print("K1:", KEY.hex())
print("K2:", KEY2.hex())

SELECTED = [1, 21, 41, 61, 81]
rows = []
for sr in SELECTED:
    msg = messages[sr - 1][1]
    for a in ALGOS:
        m1, m2 = hmac_hex(KEY, a, msg), hmac_hex(KEY2, a, msg)
        cb = changed_bits(m1, m2)
        rows.append({"Sr_No": sr, "Message": msg, "Algorithm": HMAC_NAMES[a],
                     "Changed_Bits": cb, "Total_Bits": BITS[a],
                     "Difference_%": round(cb / BITS[a] * 100, 2)})
df_key = pd.DataFrame(rows)
key_sens = df_key.groupby("Algorithm", sort=False)["Difference_%"].mean()
display(df_key.head(4))
print(key_sens.round(3).to_frame("Average difference (%)"))

# --------------------------------------------------------------
# 11. Part H – HMAC avalanche
# --------------------------------------------------------------

ms = summary(res["hmac_av"], HMAC_NAMES)
print(pd.DataFrame([{"Algorithm": HASH_NAMES[a], "Hash Avalanche (%)": round(hs[a]["avg"], 3),
               "HMAC Avalanche (%)": round(ms[a]["avg"], 3),
               "HMAC Min (%)": round(ms[a]["mn"], 3), "HMAC Max (%)": round(ms[a]["mx"], 3)}
              for a in ALGOS]))

# --------------------------------------------------------------
# 12. Graphs
# --------------------------------------------------------------

def make_pngs(hs, ms, key_sens, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    labels = [HASH_NAMES[a] for a in ALGOS]
    hlabels = [HMAC_NAMES[a] for a in ALGOS]
    colors = ["#4C72B0", "#55A868", "#C44E52", "#8172B2"]

    def single(fname, ttl, lab, vals, ylab, xlab, err=None):
        fig, ax = plt.subplots(figsize=(7, 4.5))
        bars = ax.bar(lab, vals, color=colors, yerr=err, capsize=5 if err else 0)
        ax.axhline(50, ls="--", c="grey", lw=1, label="Ideal 50%")
        ax.set_ylim(0, 70)
        ax.set_title(ttl, fontweight="bold")
        ax.set_ylabel(ylab)
        ax.set_xlabel(xlab)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, 2, f"{v:.2f}%", ha="center", color="white",
                    fontweight="bold")
        ax.legend(loc="upper right")
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, fname), dpi=200)
        plt.close(fig)

    def minmax(s):
        return [[s[a]["avg"] - s[a]["mn"] for a in ALGOS], [s[a]["mx"] - s[a]["avg"] for a in ALGOS]]

    single("graph1_hash_avalanche.png", "Graph 1 - Average Hash Avalanche (%)", labels,
           [hs[a]["avg"] for a in ALGOS], "Avalanche (%)", "Hash algorithm (error bars = min/max)",
           minmax(hs))
    single("graph2_hmac_avalanche.png", "Graph 2 - Average HMAC Avalanche (%)", hlabels,
           [ms[a]["avg"] for a in ALGOS], "Avalanche (%)", "HMAC algorithm (error bars = min/max)",
           minmax(ms))
    single("graph4_key_sensitivity.png", "Graph 4 - Key Sensitivity (K1 vs K2, 1-bit key change)",
           hlabels, [key_sens[a] for a in ALGOS], "Changed MAC bits (%)", "HMAC algorithm")

    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = range(len(ALGOS))
    w = 0.38
    hv = [hs[a]["avg"] for a in ALGOS]
    mv = [ms[a]["avg"] for a in ALGOS]
    b1 = ax.bar([i - w / 2 for i in x], hv, w, label="Hash", color="#4C72B0")
    b2 = ax.bar([i + w / 2 for i in x], mv, w, label="HMAC", color="#DD8452")
    ax.axhline(50, ls="--", c="grey", lw=1, label="Ideal 50%")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 70)
    ax.set_ylabel("Average avalanche (%)")
    ax.set_xlabel("Underlying hash algorithm")
    ax.set_title("Graph 3 - Hash vs HMAC Avalanche (%)", fontweight="bold")
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, 2, f"{b.get_height():.2f}", ha="center",
                    color="white", fontsize=8, fontweight="bold")
    ax.legend(loc="upper right")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "graph3_hash_vs_hmac.png"), dpi=200)
    plt.close(fig)


make_pngs(hs, ms, {a: key_sens[HMAC_NAMES[a]] for a in ALGOS}, GRAPHS_DIR)
for f in sorted(os.listdir(GRAPHS_DIR)):
    display(Image(os.path.join(GRAPHS_DIR, f), width=560))

# --------------------------------------------------------------
# 13. Part I – Comparative analysis
# --------------------------------------------------------------

COMPARATIVE_TEXT = {
    5: ["Broken - practical collisions (2004); seconds on a PC",
        "Broken - practical collision shown (SHAttered, 2017)",
        "Strong - no known attack (~2^128 work)",
        "Strong - no known attack (~2^256 work)"],
    6: ["Theoretically weakened (~2^123), still not practical",
        "No practical preimage attack (2^160 generic)",
        "Strong (2^256 generic)", "Strong (2^512 generic)"],
    7: ["Hash: No | HMAC-MD5: Yes"] + [f"Hash: No | {HMAC_NAMES[a]}: Yes" for a in ALGOS[1:]],
    8: ["Hash alone: No | HMAC: Yes"] * 4,
    9: ["No (legacy only)", "No (deprecated)", "Yes", "Yes"],
}

labels = {5: "Collision Resistance", 6: "Preimage Resistance", 7: "Requires Secret Key?",
          8: "Provides Authentication?", 9: "Suitable for New Security Applications?"}
table = [["Hash Output Size (bits)"] + [BITS[a] for a in ALGOS],
         ["Average Hash Avalanche (%)"] + [round(hs[a]["avg"], 3) for a in ALGOS],
         ["Average HMAC Avalanche (%)"] + [round(ms[a]["avg"], 3) for a in ALGOS]]
table += [[labels[k]] + v for k, v in COMPARATIVE_TEXT.items()]
print(pd.DataFrame(table, columns=["Property"] + [HASH_NAMES[a] for a in ALGOS]))

# --------------------------------------------------------------
# 14. Hash vs MAC – final comparison
# --------------------------------------------------------------

SEC16 = [
    ("Input", "Message", "Message + Secret Key"),
    ("Fixed-length output", "Yes", "Yes (same size as underlying hash)"),
    ("Secret key required", "No", "Yes"),
    ("Integrity", "Limited (accidental errors only)", "Yes"),
    ("Authentication", "No", "Yes"),
    ("Tampering detection", "Only if the hash itself is protected", "Yes"),
    ("Anyone can independently generate value", "Yes", "No"),
    ("Suitable for message authentication", "No", "Yes"),
]

print(pd.DataFrame(SEC16, columns=["Property", "Cryptographic Hash", "HMAC"]))

# --------------------------------------------------------------
# 15. Discussion answers and conclusion
# Used to fill the Discussion and Conclusion sheets.
# --------------------------------------------------------------

def discussion_answers(hs, ms):
    return [
        # 1
        "A hash function takes only the message and produces a fixed-length digest; it has no key, so "
        "anyone can compute it. A MAC takes the message and a secret key, so only someone holding the key "
        "can compute or verify it. A hash gives a fingerprint of the data; a MAC gives integrity plus "
        "authentication of the sender.",
        # 2
        "Because the hash is public and keyless. An attacker who changes the message can simply recompute "
        "the hash of the new message and send both together. The receiver's check still passes, so the "
        "hash cannot tell a genuine sender from an attacker. Nothing in H(M) ties the value to a particular "
        "person.",
        # 3
        "The key is the only thing the attacker does not have. Mixing it into the computation means a valid "
        "MAC can only be produced by someone who knows K. That is what turns an integrity check into an "
        "authentication check and prevents an attacker from forging a MAC for a modified message.",
        # 4
        "The MAC changes completely. In Part E all 100 modified messages produced a different HMAC-SHA256 "
        "from the original, so the receiver's recalculated MAC did not match the received MAC and "
        "verification failed (tampering detected in 100/100 cases). Around half the output bits flipped "
        f"(HMAC-SHA256 average {ms['sha256']['avg']:.2f}%).",
        # 5
        "The MAC also changes completely even though the message is the same. In Part G flipping just one "
        "bit of the 256-bit key changed roughly half of the MAC bits for all four algorithms. So a MAC made "
        "with a different key will never verify, which shows HMAC is highly sensitive to the key.",
        # 6
        f"Both behave almost identically. Average hash avalanche: MD5 {hs['md5']['avg']:.2f}%, SHA-1 "
        f"{hs['sha1']['avg']:.2f}%, SHA-256 {hs['sha256']['avg']:.2f}%, SHA-512 {hs['sha512']['avg']:.2f}%. "
        f"Average HMAC avalanche: {ms['md5']['avg']:.2f}%, {ms['sha1']['avg']:.2f}%, "
        f"{ms['sha256']['avg']:.2f}%, {ms['sha512']['avg']:.2f}%. All are close to the ideal 50%. HMAC "
        "inherits the diffusion of the underlying hash; the key does not weaken or strengthen it. Longer "
        "outputs (SHA-512) show a narrower spread between minimum and maximum.",
        # 7
        "No. HMAC output is the same size as the underlying hash: HMAC-MD5 = 128 bits, HMAC-SHA1 = 160, "
        "HMAC-SHA256 = 256, HMAC-SHA512 = 512 bits. This was confirmed in the experiment (32, 40, 64 and "
        "128 hex characters). It can be truncated by a protocol, but HMAC itself does not change it.",
        # 8
        "SHA-256 has no known collision or practical attacks and gives a 256-bit output, while MD5 is "
        "cryptographically broken for collisions and has only 128 bits. Although HMAC-MD5 is not directly "
        "broken by MD5 collisions, standards (NIST, IETF) deprecate MD5, its security margin is small, and "
        "using a broken primitive is poor practice. HMAC-SHA256 is the modern standard (TLS, JWT, AWS "
        "signing).",
        # 9
        "No. A ~50% avalanche is a necessary property but not sufficient. MD5 and SHA-1 also showed ~50% "
        "in this experiment, yet both have practical collision attacks. Security depends on resistance to "
        "collision, preimage and second-preimage attacks, which requires mathematical cryptanalysis, not "
        "just bit-flip statistics on 100 samples.",
        # 10
        "(1) Password storage - systems store a salted, deliberately slow hash (e.g. PBKDF2 or Argon2) "
        "instead of the plain password. (2) File/software integrity - download sites "
        "publish SHA-256 checksums so users can check the file was not corrupted. Other: Git commit IDs, "
        "digital-signature pre-hashing, blockchain.",
        # 11
        "(1) API request authentication - e.g. AWS Signature v4 and webhook signatures (Stripe, GitHub) "
        "sign each request with HMAC-SHA256 using a shared secret. (2) Secure network protocols - TLS, "
        "IPsec and SSH use HMAC to check that each packet is authentic and unmodified. Other: JWT (HS256) "
        "session tokens, OTP generation (HOTP/TOTP).",
        # 12
        "Because a valid HMAC can only be produced with the secret key, which only the sender and receiver "
        "share. If the received MAC matches the receiver's own calculation, the message must have come from "
        "a key holder and was not changed. An ordinary hash can be computed by anyone, including an "
        "attacker, so a matching hash proves nothing about the origin.",
        # 13 (PDF Q4)
        "No (with a secure hash and secret key). Changing the message changes the MAC, and without K the "
        "attacker cannot compute the new value. Guessing it means guessing a 256-bit (HMAC-SHA256) output "
        "or recovering the key, which is infeasible. Reusing the old MAC fails because it was computed for "
        "the original message.",
        # 14 (PDF Q8)
        "Their goals are different. A normal hash is meant to be publicly verifiable by anyone (checksums, "
        "fingerprints), so it must not need a secret. HMAC is meant to prove that a message came from a "
        "specific party, so it needs something only that party (and the receiver) has: the secret key.",
        # 15 (PDF Q14)
        "Sender and receiver share a key. The sender computes HMAC(K, packet) over the header and payload and "
        "appends it. The receiver recomputes HMAC(K, received packet) and compares (constant-time). If even "
        "one bit was altered in transit the MACs differ and the packet is dropped. Adding a sequence number "
        "inside the MAC also stops replay. This is exactly how IPsec ESP/AH and TLS record protection work.",
        # 16 (PDF Q15)
        "They solve different problems. Hashes are used where public verification or key-free fingerprints "
        "are needed: hashing certificates and messages before digital signatures, hashing transcripts, key "
        "derivation, password storage. MACs are used once a shared key exists, to authenticate every data "
        "packet cheaply. TLS uses SHA-256 inside signatures and its handshake, then HMAC/AEAD to protect "
        "each record.",
    ]


def conclusion_text(hs, ms):
    return (
        "This experiment showed that a cryptographic hash and an HMAC solve different problems. A hash "
        "takes only the message, so anyone can recompute it; it detects accidental change but cannot "
        "authenticate the sender, because an attacker can modify a message and simply recompute its hash. "
        "HMAC mixes a secret key into the hash, so only key holders can produce a valid MAC, giving both "
        "integrity and authentication.\n\n"
        f"All four hash functions showed a strong avalanche effect across the 100 message pairs, averaging "
        f"{hs['md5']['avg']:.2f}% (MD5), {hs['sha1']['avg']:.2f}% (SHA-1), {hs['sha256']['avg']:.2f}% "
        f"(SHA-256) and {hs['sha512']['avg']:.2f}% (SHA-512). The HMAC versions behaved almost identically "
        f"(about {min(v['avg'] for v in ms.values()):.1f}-{max(v['avg'] for v in ms.values()):.1f}%). A "
        "single-character change in the message, or a single-bit change in the key, altered roughly half "
        "of the output bits. As a result, every tampered message failed verification.\n\n"
        "However, a 50% avalanche does not prove security: MD5 and SHA-1 have practical collision attacks, "
        "while SHA-256 and SHA-512 remain collision resistant. HMAC-SHA256 is therefore the right choice for "
        "real applications such as API request signing, JWT tokens and packet authentication in TLS and IPsec."
    )


conclusion = conclusion_text(hs, ms)
print(conclusion)
print("\nWord count:", len(conclusion.split()))

# --------------------------------------------------------------
# 16. Export to the template workbook
# --------------------------------------------------------------

THIN = Side(style="thin")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
HEAD_FILL = PatternFill("solid", fgColor="D9EAF7")
HEAD_FONT = Font(bold=True)
HEAD_ALIGN = Alignment(horizontal="center", vertical="center", wrap_text=True)
WRAP = Alignment(vertical="top", wrap_text=True)


def header(ws, row, values, col=1):
    for i, v in enumerate(values):
        c = ws.cell(row=row, column=col + i, value=v)
        c.font, c.fill, c.alignment, c.border = HEAD_FONT, HEAD_FILL, HEAD_ALIGN, BORDER


def cell(ws, row, col, value, wrap=False, fmt=None, bold=False):
    c = ws.cell(row=row, column=col, value=value)
    c.border = BORDER
    if wrap:
        c.alignment = WRAP
    if fmt:
        c.number_format = fmt
    if bold:
        c.font = Font(bold=True)
    return c


def title(ws, row, text):
    c = ws.cell(row=row, column=1, value=text)
    c.font = Font(bold=True, size=13)


def place_after(wb, sheet_name, after_name):
    ws = wb[sheet_name]
    wb.move_sheet(ws, offset=wb.sheetnames.index(after_name) + 1 - wb.sheetnames.index(sheet_name))


def fill_workbook(template, output, messages, res):
    """Write all results into the provided template workbook."""
    wb = load_workbook(template)
    key1, key2 = KEY, res["key2"]
    hs, ms = summary(res["hash_av"], HASH_NAMES), summary(res["hmac_av"], HMAC_NAMES)

    # ---- Student_Key ----
    sk = wb["Student_Key"]
    sk["B2"] = STUDENT_NAME
    sk["B4"] = CLASS_DIV
    sk["B5"] = UID
    sk["B7"] = key1.hex()
    sk["A10"] = "Note"
    sk["A10"].font = Font(bold=True)
    sk["B10"] = ("The 64-hex-character key is used as 32 raw bytes; the same key is used "
                 "for all four HMAC algorithms.")
    sk["B10"].alignment = WRAP
    sk.row_dimensions[10].height = 45

    # ---- Hash_Values / HMAC_Values (Parts A, C) ----
    for sheet, data in (("Hash_Values", res["hash"]), ("HMAC_Values", res["hmac"])):
        ws = wb[sheet]
        for i, (sr, o, m, row) in enumerate(data, start=2):
            for j, a in enumerate(ALGOS):
                ws.cell(i, 4 + 2 * j, row[a][0])
                ws.cell(i, 5 + 2 * j, row[a][1])

    # ---- Hash_Avalanche / HMAC_Avalanche (Parts B, H) ----
    for sheet, rows in (("Hash_Avalanche", res["hash_av"]), ("HMAC_Avalanche", res["hmac_av"])):
        ws = wb[sheet]
        for i, (sr, alg, o, m, cb, tb) in enumerate(rows, start=2):
            assert ws.cell(i, 1).value == sr and ws.cell(i, 2).value == alg
            ws.cell(i, 3, o)
            ws.cell(i, 4, m)
            ws.cell(i, 5, cb)
            ws.cell(i, 7, f"=E{i}/F{i}*100").number_format = "0.00"

    # ---- Avalanche_Summary (Part B table + Part H comparison) ----
    sm = wb.create_sheet("Avalanche_Summary")
    title(sm, 1, "Part B - Hash Avalanche Summary (100 message pairs per algorithm)")
    header(sm, 2, ["Algorithm", "Avg Changed Bits", "Total Bits",
                   "Average Avalanche (%)", "Minimum Avalanche (%)", "Maximum Avalanche (%)"])
    rng = "Hash_Avalanche!$B$2:$B$401"
    for i, a in enumerate(ALGOS, start=3):
        cell(sm, i, 1, HASH_NAMES[a], bold=True)
        cell(sm, i, 2, f"=AVERAGEIF({rng},A{i},Hash_Avalanche!$E$2:$E$401)", fmt="0.00")
        cell(sm, i, 3, BITS[a])
        cell(sm, i, 4, f"=AVERAGEIF({rng},A{i},Hash_Avalanche!$G$2:$G$401)", fmt="0.00")
        cell(sm, i, 5, f"=_xlfn.MINIFS(Hash_Avalanche!$G$2:$G$401,{rng},A{i})", fmt="0.00")
        cell(sm, i, 6, f"=_xlfn.MAXIFS(Hash_Avalanche!$G$2:$G$401,{rng},A{i})", fmt="0.00")

    title(sm, 9, "Part H - HMAC Avalanche Summary (same key K1, 100 message pairs per algorithm)")
    header(sm, 10, ["Algorithm", "Avg Changed Bits", "Total Bits",
                    "Average Avalanche (%)", "Minimum Avalanche (%)", "Maximum Avalanche (%)"])
    rng = "HMAC_Avalanche!$B$2:$B$401"
    for i, a in enumerate(ALGOS, start=11):
        cell(sm, i, 1, HMAC_NAMES[a], bold=True)
        cell(sm, i, 2, f"=AVERAGEIF({rng},A{i},HMAC_Avalanche!$E$2:$E$401)", fmt="0.00")
        cell(sm, i, 3, BITS[a])
        cell(sm, i, 4, f"=AVERAGEIF({rng},A{i},HMAC_Avalanche!$G$2:$G$401)", fmt="0.00")
        cell(sm, i, 5, f"=_xlfn.MINIFS(HMAC_Avalanche!$G$2:$G$401,{rng},A{i})", fmt="0.00")
        cell(sm, i, 6, f"=_xlfn.MAXIFS(HMAC_Avalanche!$G$2:$G$401,{rng},A{i})", fmt="0.00")

    title(sm, 17, "Part H - Hash Avalanche vs HMAC Avalanche (used for Graph 3)")
    header(sm, 18, ["Algorithm", "Hash Avalanche (%)", "HMAC Avalanche (%)", "Difference (pp)"])
    for k, a in enumerate(ALGOS):
        r = 19 + k
        cell(sm, r, 1, HASH_NAMES[a], bold=True)
        cell(sm, r, 2, f"=D{3 + k}", fmt="0.00")
        cell(sm, r, 3, f"=D{11 + k}", fmt="0.00")
        cell(sm, r, 4, f"=C{r}-B{r}", fmt="0.00")

    title(sm, 25, "Part G - Average Key Sensitivity (5 selected messages, K1 vs K2) (used for Graph 4)")
    header(sm, 26, ["Algorithm", "Avg Changed Bits", "Total Bits", "Avg Difference (%)"])
    rng = "Key_Sensitivity!$E$2:$E$21"
    for k, a in enumerate(ALGOS):
        r = 27 + k
        cell(sm, r, 1, HMAC_NAMES[a], bold=True)
        cell(sm, r, 2, f"=AVERAGEIF({rng},A{r},Key_Sensitivity!$H$2:$H$21)", fmt="0.00")
        cell(sm, r, 3, BITS[a])
        cell(sm, r, 4, f"=AVERAGEIF({rng},A{r},Key_Sensitivity!$J$2:$J$21)", fmt="0.00")
    for col, w in zip("ABCDEF", (16, 18, 12, 22, 22, 22)):
        sm.column_dimensions[col].width = w
    place_after(wb, "Avalanche_Summary", "HMAC_Avalanche")

    # ---- Tampering_Test (Part E) ----
    tt = wb["Tampering_Test"]
    msg_lookup = {sr: (o, m) for sr, o, m in messages}
    for r in range(2, tt.max_row + 1):
        sr, mtype, msg = tt.cell(r, 1).value, tt.cell(r, 2).value, tt.cell(r, 3).value
        if sr is None:
            continue
        orig = msg_lookup[sr][0]
        sent_mac = hmac_hex(key1, "sha256", orig)   # sender's MAC
        recalc = hmac_hex(key1, "sha256", msg)      # receiver's MAC
        tt.cell(r, 5, sent_mac)
        tt.cell(r, 6, sent_mac)
        tt.cell(r, 7, recalc)
        tt.cell(r, 8, f'=IF(F{r}=G{r},"Yes","No")')
        tt.cell(r, 9, f'=IF(H{r}="Yes","No","Yes")')
    tt["K1"] = "Note"
    tt["K1"].font = Font(bold=True)
    tt["K2"] = ("Sender computes HMAC-SHA256(K1, original message) and sends it with the message. "
                "Receiver recomputes HMAC-SHA256(K1, received message). For 'Original' rows the "
                "received message is unaltered; for 'Modified' rows it has been tampered with in "
                "transit while the attacker cannot produce a new MAC without K1.")
    tt["K2"].alignment = WRAP
    tt.column_dimensions["K"].width = 60
    tt["K4"] = "Tampering detected (Modified rows)"
    tt["L4"] = '=COUNTIFS(B2:B201,"Modified",I2:I201,"Yes")'
    tt["K5"] = "False alarms (Original rows)"
    tt["L5"] = '=COUNTIFS(B2:B201,"Original",I2:I201,"Yes")'
    for c in ("K4", "K5"):
        tt[c].font = Font(bold=True)

    # ---- MAC_Verification (Part F) ----
    mv = wb.create_sheet("MAC_Verification")
    title(mv, 1, "Part F - Receiver-side MAC Verification (HMAC-SHA256, key K1)")
    header(mv, 3, ["Case", "Message Received", "Received MAC (sent by sender)",
                   "Recalculated MAC (by receiver)", "Verification"])
    cases = [
        ("Transfer Rs.1000 to Account A", "Transfer Rs.1000 to Account A", "Original"),
        ("Transfer Rs.1000 to Account A", "Transfer Rs.9000 to Account A", "Modified"),
        (messages[0][1], messages[0][1], "Original"),
        (messages[0][1], messages[0][2], "Modified"),
        (messages[1][1], messages[1][1], "Original"),
        (messages[1][1], messages[1][2], "Modified"),
    ]
    for i, (sent, received, case) in enumerate(cases, start=4):
        sent_mac = hmac_hex(key1, "sha256", sent)
        assert verify_mac(key1, "sha256", received, sent_mac) == (case == "Original")
        cell(mv, i, 1, case, bold=True)
        cell(mv, i, 2, received)
        cell(mv, i, 3, sent_mac)
        cell(mv, i, 4, hmac_hex(key1, "sha256", received))
        cell(mv, i, 5, f'=IF(C{i}=D{i},"PASS","FAIL")')
    mv["A11"] = "Sender:   Message + K1 -> HMAC -> transmits (Message, MAC)"
    mv["A12"] = "Receiver: Received Message + K1 -> HMAC -> compare with received MAC -> PASS if equal, else FAIL"
    for col, w in zip("ABCDE", (12, 34, 70, 70, 14)):
        mv.column_dimensions[col].width = w
    place_after(wb, "MAC_Verification", "Tampering_Test")

    # ---- Key_Sensitivity (Part G) ----
    ks = wb["Key_Sensitivity"]
    name_to_algo = {v: k for k, v in HMAC_NAMES.items()}
    for r in range(2, ks.max_row + 1):
        msg, alg = ks.cell(r, 2).value, ks.cell(r, 5).value
        if msg is None:
            continue
        a = name_to_algo[alg]
        m1, m2 = hmac_hex(key1, a, msg), hmac_hex(key2, a, msg)
        ks.cell(r, 3, key1.hex())
        ks.cell(r, 4, key2.hex())
        ks.cell(r, 6, m1)
        ks.cell(r, 7, m2)
        ks.cell(r, 8, changed_bits(m1, m2))
        ks.cell(r, 10, f"=H{r}/I{r}*100").number_format = "0.00"
    ks["L1"] = "Note"
    ks["L1"].font = Font(bold=True)
    ks["L2"] = ("Key_1 = UID-derived key K1. Key_2 = K1 with only its last bit flipped "
                "(the two keys differ in exactly 1 of 256 bits). The message is unchanged.")
    ks["L2"].alignment = WRAP
    ks.column_dimensions["L"].width = 55

    # ---- Comparative_Analysis (Part I) ----
    ca = wb["Comparative_Analysis"]
    comp = {
        2: [128, 160, 256, 512],
        3: [f"=Avalanche_Summary!D{3 + k}" for k in range(4)],
        4: [f"=Avalanche_Summary!D{11 + k}" for k in range(4)],
        **COMPARATIVE_TEXT,
    }
    for r, vals in comp.items():
        for j, v in enumerate(vals):
            c = ca.cell(r, 2 + j, v)
            c.alignment = Alignment(vertical="top", wrap_text=True)
            if r in (3, 4):
                c.number_format = "0.00"
    for r in range(5, 10):
        ca.row_dimensions[r].height = 45
    ca.column_dimensions["B"].width = ca.column_dimensions["C"].width = 30
    ca.column_dimensions["D"].width = ca.column_dimensions["E"].width = 30

    # ---- Hash_vs_HMAC (Part D + Section 16) ----
    hv = wb.create_sheet("Hash_vs_HMAC")
    title(hv, 1, "Part D - Hash vs HMAC")
    header(hv, 2, ["Property", "Hash", "HMAC"])
    part_d = PART_D
    for i, row in enumerate(part_d, start=3):
        for j, v in enumerate(row):
            cell(hv, i, 1 + j, v, wrap=True, bold=(j == 0))

    hv["A10"] = "Why a hash alone cannot authenticate the sender"
    hv["A10"].font = Font(bold=True)
    hv["A11"] = (
        "A hash function is public and keyless: H(M) depends only on the message. If an attacker "
        "intercepts (M, H(M)), they can change the message to M', compute H(M') themselves and "
        "forward (M', H(M')). The receiver recomputes H(M'), it matches, and the forgery is accepted. "
        "Because anyone can produce a valid hash for any message, a matching hash says nothing about "
        "who produced it. HMAC mixes a secret key into the computation, so only a party holding K can "
        "produce HMAC(K, M); a matching MAC therefore proves both that the message is unchanged and "
        "that it came from someone who holds the shared key.")
    hv.merge_cells("A11:C11")
    hv["A11"].alignment = WRAP
    hv.row_dimensions[11].height = 110

    title(hv, 13, "Section 16 - Hash vs MAC: Final Comparison")
    header(hv, 14, ["Property", "Cryptographic Hash", "HMAC"])
    sec16 = SEC16
    for i, row in enumerate(sec16, start=15):
        for j, v in enumerate(row):
            cell(hv, i, 1 + j, v, wrap=True, bold=(j == 0))
    for col, w in zip("ABC", (40, 50, 50)):
        hv.column_dimensions[col].width = w
    place_after(wb, "Hash_vs_HMAC", "Comparative_Analysis")

    # ---- Graphs (native Excel charts + observations) ----
    gr = wb["Graphs"]
    obs = [
        f"All four hash functions average close to 50% (MD5 {hs['md5']['avg']:.2f}%, SHA-1 "
        f"{hs['sha1']['avg']:.2f}%, SHA-256 {hs['sha256']['avg']:.2f}%, SHA-512 "
        f"{hs['sha512']['avg']:.2f}%). A one-character change flips about half the output bits.",
        f"HMAC averages are also about 50% (HMAC-MD5 {ms['md5']['avg']:.2f}%, HMAC-SHA1 "
        f"{ms['sha1']['avg']:.2f}%, HMAC-SHA256 {ms['sha256']['avg']:.2f}%, HMAC-SHA512 "
        f"{ms['sha512']['avg']:.2f}%). Adding the key keeps the avalanche property.",
        "Hash and HMAC bars are almost equal for every algorithm (difference < 1 percentage point). "
        "Keyed and unkeyed hashing show the same diffusion; larger outputs give a narrower min-max spread.",
        "Flipping a single bit of the key changes roughly half of the MAC bits for every algorithm, "
        "so the MAC is completely different. HMAC is highly sensitive to the key.",
    ]
    for i, o in enumerate(obs, start=2):
        gr.cell(i, 3, o).alignment = WRAP
        gr.row_dimensions[i].height = 75

    def bar_chart(ttl, cats_ref, data_refs, y_title, x_title):
        ch = BarChart()
        ch.type = "col"
        ch.title = ttl
        ch.y_axis.title = y_title
        ch.x_axis.title = x_title
        ch.y_axis.scaling.min = 0
        ch.y_axis.scaling.max = 60
        ch.y_axis.majorGridlines = None
        for ref in data_refs:
            ch.add_data(ref, titles_from_data=True)
        ch.set_categories(cats_ref)
        ch.dataLabels = DataLabelList()
        ch.dataLabels.showVal = True
        ch.dataLabels.showSerName = False
        ch.dataLabels.showCatName = False
        ch.dataLabels.showLegendKey = False
        ch.dataLabels.showPercent = False
        ch.dataLabels.numFmt = "0.00"
        ch.height, ch.width = 8, 15
        ch.x_axis.delete = False
        ch.y_axis.delete = False
        return ch

    S = sm
    g1 = bar_chart("Graph 1 - Average Hash Avalanche (%)",
                   Reference(S, min_col=1, min_row=3, max_row=6),
                   [Reference(S, min_col=4, min_row=2, max_row=6)], "Avalanche (%)", "Hash Algorithm")
    g2 = bar_chart("Graph 2 - Average HMAC Avalanche (%)",
                   Reference(S, min_col=1, min_row=11, max_row=14),
                   [Reference(S, min_col=4, min_row=10, max_row=14)], "Avalanche (%)", "HMAC Algorithm")
    g3 = bar_chart("Graph 3 - Hash vs HMAC Avalanche (%)",
                   Reference(S, min_col=1, min_row=19, max_row=22),
                   [Reference(S, min_col=2, min_row=18, max_row=22),
                    Reference(S, min_col=3, min_row=18, max_row=22)], "Avalanche (%)", "Algorithm")
    g4 = bar_chart("Graph 4 - Key Sensitivity: MAC Bits Changed when Key Changes (%)",
                   Reference(S, min_col=1, min_row=27, max_row=30),
                   [Reference(S, min_col=4, min_row=26, max_row=30)], "Changed MAC bits (%)",
                   "HMAC Algorithm")
    for ch in (g1, g2, g4):
        ch.legend = None
    g3.legend.position = "b"
    g3.width = 17
    gr.add_chart(g1, "A8")
    gr.add_chart(g2, "C8")
    gr.add_chart(g3, "A26")
    gr.add_chart(g4, "C26")

    # ---- Discussion ----
    dq = wb["Discussion"]
    ans = discussion_answers(hs, ms)
    for i, a in enumerate(ans[:12], start=2):
        dq.cell(i, 2, a).alignment = WRAP
        dq.cell(i, 1).alignment = WRAP
        dq.row_dimensions[i].height = 105
    extra_q = [
        ("Can an attacker modify a message and calculate a valid HMAC without knowing the secret key? Explain.", ans[12]),
        ("Why does HMAC use a secret key while a normal hash does not?", ans[13]),
        ("How can HMAC be used to detect modification of a network packet?", ans[14]),
        ("Why might a system use both hashing and MACs in different parts of a security protocol?", ans[15]),
    ]
    for k, (q, a) in enumerate(extra_q):
        r = 14 + k
        c1 = dq.cell(r, 1, q)
        c2 = dq.cell(r, 2, a)
        src = dq.cell(13, 1)
        for c in (c1, c2):
            c.border = copy(src.border)
            c.font = copy(src.font)
            c.alignment = WRAP
        dq.row_dimensions[r].height = 105

    # ---- Conclusion ----
    cs = wb.create_sheet("Conclusion")
    title(cs, 1, "Final Conclusion (150-200 words)")
    text = conclusion_text(hs, ms)
    cs["A3"] = text
    cs["A3"].alignment = WRAP
    cs.merge_cells("A3:A3")
    cs.column_dimensions["A"].width = 120
    cs.row_dimensions[3].height = 230
    cs["A5"] = f"Word count: {len(text.split())}"
    place_after(wb, "Conclusion", "Discussion")

    wb.calculation.fullCalcOnLoad = True
    wb.save(output)



fill_workbook(INPUT_XLSX, OUTPUT_XLSX, messages, res)
print("Saved:", OUTPUT_XLSX)

# --------------------------------------------------------------
# Demo – reproduce any record
# --------------------------------------------------------------

SR = 1
msg = messages[SR - 1][1]
print("Message:", msg)
for a in ALGOS:
    print(f"{HASH_NAMES[a]:<12}", hash_hex(a, msg))
for a in ALGOS:
    print(f"{HMAC_NAMES[a]:<12}", hmac_hex(KEY, a, msg))
