# CNS Lab Exam Code

Simple, commented Python implementations of the Cryptography and Network Security lab algorithms.
Each file runs on its own (`python 1_rsa.py`) and prints a small worked example.

| Folder | Experiment | Files |
|---|---|---|
| `exp1` | Probabilistic primality testing | Fermat, Euler, Miller-Rabin, modular power (square-and-multiply) |
| `exp2` | Classical symmetric ciphers | Caesar, Monoalphabetic, Vigenere, Playfair, Hill (2x2) |
| `exp3` | Asymmetric cryptography | RSA, ElGamal, Diffie-Hellman, ECC |
| `exp7` | Hashing and HMAC | MD5 / SHA-1 / SHA-256 / SHA-512, avalanche effect, file integrity, HMAC (built-in and manual) |
| `exp8` | Digital signatures | ECDSA (P-256), RSA-PSS (3072-bit) |

## Requirements
- Python 3.8+
- Exp 1, 2, 3, 7: no extra packages
- Exp 8: `pip install cryptography`

## Example keys used
| Cipher | Key | Example |
|---|---|---|
| Caesar | 3 | HELLO WORLD -> KHOOR ZRUOG |
| Monoalphabetic | QWERTYUIOPASDFGHJKLZXCVBNM | HELLO -> ITSSG |
| Vigenere | LEMON | ATTACK AT DAWN -> LXFOPV EF RNHR |
| Playfair | MONARCHY | INSTRUMENTS -> GATLMZCLRQXA |
| Hill | [[3, 3], [2, 5]] | HELP -> HIAT |
| RSA | p=3, q=11, e=7 | m=2 -> c=29 |
| ElGamal | p=23, x=6, k=3 | m=10 -> (c1, c2) = (10, 14) |
| Diffie-Hellman | p=23, g=5, a=6, b=15 | shared key = 2 |
| ECC | y^2 = x^3 + 2x + 2 (mod 17), G=(5,1) | 2G = (6, 3) |
