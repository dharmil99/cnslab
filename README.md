# CNS Lab Exam Code

Simple, commented Python implementations of the Cryptography and Network Security lab algorithms.
Each file runs on its own (`python 1_rsa.py`) and prints a small worked example.

| Folder | Experiment | Files |
|---|---|---|
| `exp1` | Probabilistic primality testing | Fermat, Euler, Miller-Rabin, modular power (square-and-multiply) |
| `exp2` | Classical symmetric ciphers | Caesar, Monoalphabetic, Vigenere, Playfair, Hill (2x2), Hill (any n x n: 3x3, 4x4, ...) |
| `exp3` | Asymmetric cryptography | RSA, ElGamal, Diffie-Hellman, ECC |
| `exp7` | Hashing and HMAC | MD5 / SHA-1 / SHA-256 / SHA-512, avalanche effect, file integrity, HMAC built by hand |
| `exp8` | Digital signatures (from scratch, only `hashlib`) | ECDSA (small Exp 3 curve, hand-checkable), RSA-PSS (simplest version); `full_versions/` has ECDSA on P-256 and standard-exact RSA-PSS |

## One file per algorithm (from the lab submissions)
| Folder | Files | Notes |
|---|---|---|
| `exp7/from_scratch/` | `1_md5.py`, `2_sha1.py`, `3_sha256.py`, `4_sha512.py`, `5_hmac.py` | Hashes written from scratch (padding + compression function); each checks itself against `hashlib`. HMAC built from the RFC 2104 formula for all four hashes. No extra packages. |

## Full lab submissions (single files, original code - these two use libraries)
| File | What it is | Run |
|---|---|---|
| `exp7/exp7_submission_full.py` | Complete Exp 7 notebook as one script: MD5, SHA-1, SHA-256, SHA-512 and HMAC **from scratch**, self-test against published vectors, Parts A-I, graphs, Excel export | `python3 exp7/exp7_submission_full.py` (needs `pandas matplotlib openpyxl` and `Hash_and_MAC_Database.xlsx`) |
| `exp8/exp8_submission_full.py` | Complete Exp 8 source code (common, crypto_ops, keygen, sign, verify, tamper, bench, plot + Dockerfile) as one script with sub-commands | `STUDENT_UID=2024300124 python3 exp8/exp8_submission_full.py keygen ecdsa` (needs `cryptography liboqs-python pandas matplotlib`) |

## Requirements
- Python 3.8+
- No extra packages: everything uses only the Python standard library (`hashlib`, `random`, `os`)

## Example keys used
| Cipher | Key | Example |
|---|---|---|
| Caesar | 3 | HELLO WORLD -> KHOOR ZRUOG |
| Monoalphabetic | QWERTYUIOPASDFGHJKLZXCVBNM | HELLO -> ITSSG |
| Vigenere | LEMON | ATTACK AT DAWN -> LXFOPV EF RNHR |
| Playfair | MONARCHY | INSTRUMENTS -> GATLMZCLRQXA |
| Hill | [[3, 3], [2, 5]] | HELP -> HIAT |
| Hill 3x3 | GYBNQKURP | ACT -> POH, CAT -> FIN |
| RSA | p=3, q=11, e=7 | m=2 -> c=29 |
| ElGamal | p=23, x=6, k=3 | m=10 -> (c1, c2) = (10, 14) |
| Diffie-Hellman | p=23, g=5, a=6, b=15 | shared key = 2 |
| ECC | y^2 = x^3 + 2x + 2 (mod 17), G=(5,1) | 2G = (6, 3) |
| ECDSA | same curve, n=19, d=7, k=3 | signature (r, s) = (10, 8) |
