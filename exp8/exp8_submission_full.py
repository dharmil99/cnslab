# ==============================================================
# EXPERIMENT 8 : EVALUATION OF CLASSICAL AND POST-QUANTUM DIGITAL SIGNATURE
#                ALGORITHMS (ECDSA, RSA-PSS, ML-DSA-44, SLH-DSA-SHA2-128s)
# Vansh Lathiya | UID 2024300124 | B3
#
# All code from the submitted source_code/ folder (common.py, crypto_ops.py,
# keygen.py, sign.py, verify.py, tamper.py, bench.py, plot.py) in ONE file.
# Each old script is now a sub-command:
#
#   python3 exp8_submission_full.py keygen <ecdsa|rsapss|mldsa|slhdsa>
#   python3 exp8_submission_full.py sign   <alg>
#   python3 exp8_submission_full.py verify <alg> [document] [public_key] [signature]
#   python3 exp8_submission_full.py tamper <doc|sig> <file>
#   python3 exp8_submission_full.py bench  [results.csv]
#   python3 exp8_submission_full.py plot   [results.csv]
#
# Needs: STUDENT_UID set in the environment (export STUDENT_UID=2024300124)
#        pip install cryptography liboqs-python pandas matplotlib
#        (first "import oqs" downloads and builds liboqs - a few minutes)
# The Dockerfile used for the sender / receiver containers is at the bottom.
# ==============================================================

# ==============================================================
# common.py
# common.py - shared helpers for CNS Experiment 8 (Digital Signatures)
# Student : Vansh Lathiya
# UID     : read from the STUDENT_UID environment variable (2024300124)
#
# Used by keygen.py, sign.py, verify.py, tamper.py, bench.py and plot.py
# in BOTH the sender and the receiver container.
# ==============================================================
import os
import sys
import time
import hashlib

# ---------------------------------------------------------------------------
# 1. Student UID (from the environment, validated)
# ---------------------------------------------------------------------------
def get_uid() -> str:
    uid = os.environ.get("STUDENT_UID", "").strip()
    if not (uid.isdigit() and len(uid) == 10):
        sys.exit(f"[ERROR] STUDENT_UID must be set to a 10-digit UID (got '{uid}'). "
                 f"Start the container with -e STUDENT_UID=<your UID>.")
    return uid

UID = get_uid()

# ---------------------------------------------------------------------------
# 2. Algorithm table  (liboqs names taken from Step D1 on this system)
# ---------------------------------------------------------------------------
ALGS = {
    "ecdsa":  {"family": "classical", "lib": "cryptography", "name": "ECDSA P-256 / SHA-256"},
    "rsapss": {"family": "classical", "lib": "cryptography", "name": "RSA-3072-PSS / SHA-256",
               "bits": 3072, "e": 65537, "salt": 32},
    "mldsa":  {"family": "post-quantum", "lib": "oqs", "name": "ML-DSA-44"},
    "slhdsa": {"family": "post-quantum", "lib": "oqs", "name": "SLH_DSA_PURE_SHA2_128S"},
}
ALG_ORDER = ["ecdsa", "rsapss", "mldsa", "slhdsa"]
LABEL = {"ecdsa": "ECDSA", "rsapss": "RSA-PSS", "mldsa": "ML-DSA", "slhdsa": "SLH-DSA"}

def check_alg(alg: str) -> str:
    alg = alg.lower()
    if alg not in ALGS:
        sys.exit(f"[ERROR] unknown algorithm '{alg}'. Use one of: {', '.join(ALG_ORDER)}")
    return alg

# ---------------------------------------------------------------------------
# 3. UID-based individualisation (Section 5 of the lab sheet)
# ---------------------------------------------------------------------------
# Order n of the P-256 group
P256_N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFF"
             "BCE6FAADA7179E84F3B9CAC2FC632551", 16)

def document_text(uid: str = UID) -> str:
    """Line 1: Transfer Rs.<A> to Account <last 4 digits>, A = 1000 + (UID mod 9000)
       Line 2: Issued by UID: <UID>"""
    a = 1000 + (int(uid) % 9000)
    return f"Transfer Rs.{a} to Account {uid[-4:]}\nIssued by UID: {uid}\n"

def ecdsa_private_scalar(uid: str = UID) -> int:
    """d = ( int(SHA-256(UID || "CNS-DSIG-ECDSA-KEY")) mod (n - 1) ) + 1"""
    digest = hashlib.sha256((uid + "CNS-DSIG-ECDSA-KEY").encode()).digest()
    return (int.from_bytes(digest, "big") % (P256_N - 1)) + 1

def bench_message(uid: str = UID) -> bytes:
    """1024-byte benchmark message seeded with the UID."""
    import random
    return random.Random(int(uid)).randbytes(1024)

def tamper_index(length: int, uid: str = UID) -> int:
    """Position to modify = UID mod (length of file in bytes)."""
    return int(uid) % length

# ---------------------------------------------------------------------------
# 4. File-name helpers
# ---------------------------------------------------------------------------
KEYS_DIR, OUTBOX, INBOX = "keys", "outbox", "inbox"

def priv_path(alg):    return os.path.join(KEYS_DIR, f"{alg}_private.key")
def pub_path(alg):     return os.path.join(OUTBOX, f"{alg}_public.key")
def sig_path(alg):     return os.path.join(OUTBOX, f"{alg}.sig")
def doc_path():        return os.path.join(OUTBOX, "document.txt")
def inbox_doc():       return os.path.join(INBOX, "document.txt")
def inbox_pub(alg):    return os.path.join(INBOX, f"{alg}_public.key")
def inbox_sig(alg):    return os.path.join(INBOX, f"{alg}.sig")

def read_bytes(p):
    with open(p, "rb") as f:
        return f.read()

def write_bytes(p, data):
    d = os.path.dirname(p)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)

# ---------------------------------------------------------------------------
# 5. Timing helper
# ---------------------------------------------------------------------------
def timed(fn, *args, **kw):
    """Run fn once; return (result, elapsed_ms) using time.perf_counter_ns()."""
    t0 = time.perf_counter_ns()
    r = fn(*args, **kw)
    t1 = time.perf_counter_ns()
    return r, (t1 - t0) / 1e6

# ==============================================================
# crypto_ops.py
# crypto_ops.py - the actual KeyGen / Sign / Verify calls for the four algorithms.
# Kept in one place so keygen.py, sign.py, verify.py and bench.py use IDENTICAL
# parameters (same hash, padding, salt length and parameter set).
# ==============================================================
import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.exceptions import InvalidSignature


PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)  # salt = digest length

# ------------------------------------------------------------------ KeyGen
def keygen(alg):
    """Return (public_key_bytes, private_key_bytes)."""
    if alg == "ecdsa":
        sk = ec.derive_private_key(ecdsa_private_scalar(), ec.SECP256R1())
    elif alg == "rsapss":
        sk = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    else:
        with oqs.Signature(ALGS[alg]["name"]) as signer:
            pk = signer.generate_keypair()
            return bytes(pk), bytes(signer.export_secret_key())
    priv = sk.private_bytes(serialization.Encoding.DER,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    return pub, priv

# ------------------------------------------------------------------ loaders
def load_signer(alg, priv_bytes):
    """Return a callable sign(data) -> signature (key parsing done outside timing)."""
    if alg == "ecdsa":
        sk = serialization.load_der_private_key(priv_bytes, password=None)
        return lambda m: sk.sign(m, ec.ECDSA(hashes.SHA256()))
    if alg == "rsapss":
        sk = serialization.load_der_private_key(priv_bytes, password=None)
        return lambda m: sk.sign(m, PSS, hashes.SHA256())
    s = oqs.Signature(ALGS[alg]["name"], priv_bytes)
    return lambda m: bytes(s.sign(m))

def load_verifier(alg, pub_bytes):
    """Return a callable verify(data, sig) -> bool."""
    if alg in ("ecdsa", "rsapss"):
        pk = serialization.load_der_public_key(pub_bytes)
        def v(m, sig):
            try:
                if alg == "ecdsa":
                    pk.verify(sig, m, ec.ECDSA(hashes.SHA256()))
                else:
                    pk.verify(sig, m, PSS, hashes.SHA256())
                return True
            except (InvalidSignature, ValueError):   # InvalidSignature raised by cryptography
                return False
        return v
    s = oqs.Signature(ALGS[alg]["name"])
    def v(m, sig):
        try:
            return bool(s.verify(m, sig, pub_bytes))   # liboqs returns a boolean
        except Exception:
            return False
    return v

# ==============================================================
# keygen.py  ->  sub-command 'keygen'
# keygen.py <alg> - generate a key pair.
# Private key -> keys/<alg>_private.key   (never leaves the container)
# Public key  -> outbox/<alg>_public.key  (published to the receiver)
# ==============================================================
def cmd_keygen(sys_argv):
    import sys

    if len(sys_argv) != 2:
        sys.exit("usage: python3 keygen.py <ecdsa|rsapss|mldsa|slhdsa>")
    alg = check_alg(sys_argv[1])

    (pub, priv), ms = timed(keygen, alg)
    write_bytes(priv_path(alg), priv)
    write_bytes(pub_path(alg), pub)

    print(f"[keygen] UID={UID}  algorithm={alg} ({ALGS[alg]['name']})")
    print(f"  private key -> {priv_path(alg):28s} {len(priv):6d} bytes")
    print(f"  public key  -> {pub_path(alg):28s} {len(pub):6d} bytes")
    print(f"  key generation time: {ms:.3f} ms")

# ==============================================================
# sign.py  ->  sub-command 'sign'
# sign.py <alg> - (1) create outbox/document.txt from the UID if missing,
# (2) read it as bytes, (3) load the private key, (4) sign,
# (5) write outbox/<alg>.sig, (6) print the signature size.
# ==============================================================
def cmd_sign(sys_argv):
    import os
    import sys
    import hashlib

    if len(sys_argv) != 2:
        sys.exit("usage: python3 sign.py <ecdsa|rsapss|mldsa|slhdsa>")
    alg = check_alg(sys_argv[1])

    if not os.path.exists(doc_path()):
        write_bytes(doc_path(), document_text().encode())
        print(f"[sign] created {doc_path()} from UID {UID}")

    M = read_bytes(doc_path())
    signer = load_signer(alg, read_bytes(priv_path(alg)))
    S, ms = timed(signer, M)
    write_bytes(sig_path(alg), S)

    print(f"[sign] algorithm={alg} ({ALGS[alg]['name']})")
    print(f"  document  : {doc_path()} ({len(M)} bytes, SHA-256 {hashlib.sha256(M).hexdigest()[:16]}...)")
    print(f"  signature -> {sig_path(alg)}  {len(S)} bytes")
    print(f"  signing time: {ms:.3f} ms")

# ==============================================================
# verify.py  ->  sub-command 'verify'
# verify.py <alg> [document] [public_key] [signature]
# Defaults: inbox/document.txt, inbox/<alg>_public.key, inbox/<alg>.sig
# Prints PASS (VALID) or FAIL (INVALID) and the verification time.
# ==============================================================
def cmd_verify(sys_argv):
    import sys

    if not 2 <= len(sys_argv) <= 5:
        sys.exit("usage: python3 verify.py <alg> [document] [public_key] [signature]")
    alg = check_alg(sys_argv[1])
    doc = sys_argv[2] if len(sys_argv) > 2 else inbox_doc()
    pub = sys_argv[3] if len(sys_argv) > 3 else inbox_pub(alg)
    sig = sys_argv[4] if len(sys_argv) > 4 else inbox_sig(alg)

    M, PK, S = read_bytes(doc), read_bytes(pub), read_bytes(sig)
    verifier = load_verifier(alg, PK)
    ok, ms = timed(verifier, M, S)

    print(f"[verify] algorithm={alg} ({ALGS[alg]['name']})")
    print(f"  document={doc}  public_key={pub}  signature={sig}")
    print(f"  RESULT: {'PASS (VALID)' if ok else 'FAIL (INVALID)'}   verification time: {ms:.3f} ms")
    sys.exit(0 if ok else 1)

# ==============================================================
# tamper.py  ->  sub-command 'tamper'
# tamper.py <doc|sig> <file> - Mallory modifies exactly one character / bit
# at index = UID mod (file length) and saves <file>.tampered.
# The original file is NOT overwritten.
# ==============================================================
def cmd_tamper(sys_argv):
    import sys

    if len(sys_argv) != 3 or sys_argv[1] not in ("doc", "sig"):
        sys.exit("usage: python3 tamper.py <doc|sig> <file>")
    mode, path = sys_argv[1], sys_argv[2]

    data = bytearray(read_bytes(path))
    i = tamper_index(len(data))
    old = data[i]

    if mode == "doc":
        # change one printable character: digits rotate 0-9, letters rotate a-z/A-Z,
        # anything else is replaced by 'X'
        c = chr(old)
        if c.isdigit():
            new = ord(str((int(c) + 1) % 10))
        elif c.islower():
            new = ord('a') + (old - ord('a') + 1) % 26
        elif c.isupper():
            new = ord('A') + (old - ord('A') + 1) % 26
        else:
            new = ord('X')
    else:
        new = old ^ 0x01            # flip the least-significant bit of one byte

    data[i] = new
    out = path + ".tampered"
    write_bytes(out, bytes(data))

    print(f"[tamper] UID={UID}  mode={mode}  file={path} ({len(data)} bytes)")
    print(f"  index = {UID} mod {len(data)} = {i}")
    if mode == "doc":
        print(f"  character changed: '{chr(old)}' -> '{chr(new)}'")
        print("  original : " + read_bytes(path).decode().replace("\n", "\\n"))
        print("  modified : " + bytes(data).decode().replace("\n", "\\n"))
    else:
        print(f"  byte changed: 0x{old:02x} -> 0x{new:02x} (one bit flipped)")
    print(f"  saved -> {out}")

# ==============================================================
# bench.py  ->  sub-command 'bench'
# bench.py - benchmark KeyGen / Sign / Verify for all four algorithms.
# * 5 warm-up runs per operation (not recorded)
# * KeyGen x20, Sign x100, Verify x100, each call timed with time.perf_counter_ns()
# * Only the cryptographic call is inside the timed region (no file I/O / network)
# * Writes results.csv  (UID in the first column)
# ==============================================================
def cmd_bench(sys_argv):
    import csv
    import sys
    import socket
    import statistics as st
    import time


    WARMUP, N_KEYGEN, N_SIGN, N_VERIFY = 5, 20, 100, 100
    OUT = sys_argv[1] if len(sys_argv) > 1 else "results.csv"
    M = bench_message()                         # 1024 bytes, random.Random(int(UID))

    def measure(fn, runs):
        for _ in range(WARMUP):
            fn()
        times, last = [], None
        for _ in range(runs):
            t0 = time.perf_counter_ns()
            last = fn()
            t1 = time.perf_counter_ns()
            times.append((t1 - t0) / 1e6)
        return times, last

    rows = []
    print(f"UID={UID}  host={socket.gethostname()}  message={len(M)} bytes")
    for alg in ALG_ORDER:
        kg_times, (pub, priv) = measure(lambda: keygen(alg), N_KEYGEN)
        sign = load_signer(alg, priv)                  # key parsing outside timing
        verify = load_verifier(alg, pub)
        sg_times, sig = measure(lambda: sign(M), N_SIGN)
        # make sure we are not timing failed operations
        assert verify(M, sig), f"{alg}: signature from signing loop does not verify!"
        vf_times, ok = measure(lambda: verify(M, sig), N_VERIFY)
        assert ok
        for op, t in (("keygen", kg_times), ("sign", sg_times), ("verify", vf_times)):
            rows.append({
                "uid": UID, "host": socket.gethostname(), "algorithm": alg, "operation": op,
                "runs": len(t), "mean_ms": round(st.mean(t), 4), "std_ms": round(st.stdev(t), 4),
                "min_ms": round(min(t), 4), "max_ms": round(max(t), 4),
                "pub_key_bytes": len(pub), "priv_key_bytes": len(priv), "sig_bytes": len(sig),
            })
            print(f"  {alg:7s} {op:7s} runs={len(t):3d}  mean={st.mean(t):10.4f} ms  "
                  f"std={st.stdev(t):9.4f}  min={min(t):9.4f}  max={max(t):9.4f}")

    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"written -> {OUT}")

# ==============================================================
# plot.py  ->  sub-command 'plot'
# plot.py [results.csv] - draw Graphs 1-7 from results.csv into graphs/.
# ==============================================================
def cmd_plot(sys_argv):
    import os
    import sys
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    CSV = sys_argv[1] if len(sys_argv) > 1 else "results.csv"
    DOC_BYTES = 59          # size of outbox/document.txt for UID 2024300124
    ENV = ("Env: Intel Xeon @ 2.10 GHz, 2 vCPU, 7.8 GiB RAM, Ubuntu 24.04, Docker 29.9.2, "
           "cryptography 50.0.1, liboqs 0.16.0")
    ORDER = ["ecdsa", "rsapss", "mldsa", "slhdsa"]
    LABEL = {"ecdsa": "ECDSA\n(P-256)", "rsapss": "RSA-PSS\n(3072)",
             "mldsa": "ML-DSA-44", "slhdsa": "SLH-DSA\nSHA2-128s"}
    COL = {"ecdsa": "#4C72B0", "rsapss": "#55A868", "mldsa": "#C44E52", "slhdsa": "#8172B2"}

    df = pd.read_csv(CSV)
    uid = str(df["uid"].iloc[0])
    os.makedirs("graphs", exist_ok=True)
    sizes = df.drop_duplicates("algorithm").set_index("algorithm").loc[ORDER]
    t = df.pivot(index="algorithm", columns="operation", values="mean_ms").loc[ORDER]
    s = df.pivot(index="algorithm", columns="operation", values="std_ms").loc[ORDER]
    x = range(len(ORDER))
    xl = [LABEL[a] for a in ORDER]
    cols = [COL[a] for a in ORDER]

    def finish(ax, fig, name, title, ylabel, log=False):
        ax.set_title(f"{title}\n(UID {uid})", fontsize=12, fontweight="bold")
        ax.set_ylabel(ylabel); ax.set_xlabel("Algorithm")
        if log: ax.set_yscale("log")
        ax.grid(axis="y", which="both", alpha=0.3)
        fig.text(0.5, 0.01, ENV, ha="center", fontsize=7, color="#555")
        fig.tight_layout(rect=(0, 0.04, 1, 1))
        fig.savefig(f"graphs/{name}.png", dpi=150); plt.close(fig)
        print("saved graphs/%s.png" % name)

    def labels(ax, bars, fmt="{:,.0f}", err=None):
        for k, b in enumerate(bars):
            top = b.get_height() + (err[k] if err is not None else 0)
            ax.annotate(fmt.format(b.get_height()), (b.get_x() + b.get_width() / 2, top),
                        ha="center", va="bottom", fontsize=8, xytext=(0, 2), textcoords="offset points")

    # Graph 1 - grouped bar: public / private key size
    fig, ax = plt.subplots(figsize=(8, 5)); w = 0.38
    b1 = ax.bar([i - w/2 for i in x], sizes["pub_key_bytes"], w, label="Public key", color="#4C72B0")
    b2 = ax.bar([i + w/2 for i in x], sizes["priv_key_bytes"], w, label="Private key", color="#DD8452")
    labels(ax, b1); labels(ax, b2); ax.set_xticks(list(x), xl); ax.legend()
    finish(ax, fig, "graph1", "Graph 1: Public- and private-key size", "Size (bytes, log scale)", log=True)

    # Graph 2 - signature size
    fig, ax = plt.subplots(figsize=(8, 5))
    labels(ax, ax.bar(xl, sizes["sig_bytes"], color=cols))
    finish(ax, fig, "graph2", "Graph 2: Signature size", "Size (bytes, log scale)", log=True)

    # Graph 3 / 4 - signing / verification time with std error bars
    for name, op, title in (("graph3", "sign", "Graph 3: Average signing time (error bar = 1 std dev)"),
                            ("graph4", "verify", "Graph 4: Average verification time (error bar = 1 std dev)")):
        fig, ax = plt.subplots(figsize=(8, 5))
        bars = ax.bar(xl, t[op], yerr=s[op], capsize=6, color=cols, ecolor="black")
        labels(ax, bars, "{:.4f}", err=list(s[op]))
        finish(ax, fig, name, title, "Time (ms, log scale)", log=True)

    # Graph 5 - key generation time
    fig, ax = plt.subplots(figsize=(8, 5))
    labels(ax, ax.bar(xl, t["keygen"], color=cols), "{:.4f}")
    finish(ax, fig, "graph5", "Graph 5: Average key-generation time", "Time (ms, log scale)", log=True)

    # Graph 6 - stacked bar: document + signature + public key
    fig, ax = plt.subplots(figsize=(8, 5))
    doc = [DOC_BYTES] * 4
    sig = list(sizes["sig_bytes"]); pub = list(sizes["pub_key_bytes"])
    ax.bar(xl, doc, label="Document", color="#999999")
    ax.bar(xl, sig, bottom=doc, label="Signature", color="#C44E52")
    ax.bar(xl, pub, bottom=[d + g for d, g in zip(doc, sig)], label="Public key", color="#4C72B0")
    for i, tot in enumerate([d + g + p for d, g, p in zip(doc, sig, pub)]):
        ax.annotate(f"{tot:,} B", (i, tot), ha="center", va="bottom", fontsize=9, xytext=(0, 2),
                    textcoords="offset points", fontweight="bold")
    ax.legend()
    finish(ax, fig, "graph6", "Graph 6: Total transmitted bytes (document + signature + public key)",
           "Bytes")

    # Graph 7 - relative to ECDSA (=1)
    fig, ax = plt.subplots(figsize=(9, 5)); w = 0.27
    for k, (op, c) in enumerate((("keygen", "#8C8C8C"), ("sign", "#C44E52"), ("verify", "#4C72B0"))):
        rel = t[op] / t.loc["ecdsa", op]
        bars = ax.bar([i + (k - 1) * w for i in x], rel, w, label={"keygen": "Key generation",
                      "sign": "Signing", "verify": "Verification"}[op], color=c)
        labels(ax, bars, "{:.2g}")
    ax.axhline(1, color="black", lw=0.8, ls="--"); ax.set_xticks(list(x), xl); ax.legend()
    finish(ax, fig, "graph7", "Graph 7: Time relative to ECDSA (ECDSA = 1)",
           "Relative time (x ECDSA, log scale)", log=True)

# ==============================================================
# main : pick the sub-command (sys_argv[0] = command name, like the old script name)
# ==============================================================
COMMANDS = {"keygen": cmd_keygen, "sign": cmd_sign, "verify": cmd_verify,
            "tamper": cmd_tamper, "bench": cmd_bench, "plot": cmd_plot}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.exit("usage: python3 exp8_submission_full.py <" + "|".join(COMMANDS) + "> [args]")
    COMMANDS[sys.argv[1]](sys.argv[1:])

# ==============================================================
# Dockerfile (sig-lab:1.0 image for the sender and receiver containers)
# ==============================================================
# FROM ubuntu:24.04
# ENV DEBIAN_FRONTEND=noninteractive
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     python3 python3-pip python3-venv git cmake ninja-build build-essential \
#     libssl-dev curl wget nano iproute2 iputils-ping tcpdump ca-certificates \
#     && rm -rf /var/lib/apt/lists/*
# RUN python3 -m venv /opt/venv
# ENV PATH="/opt/venv/bin:$PATH"
# RUN pip install --no-cache-dir cryptography matplotlib pandas liboqs-python
# # The first import makes liboqs-python download and build liboqs (a few minutes)
# RUN python3 -c "import oqs; print(oqs.oqs_version())"
# WORKDIR /lab
# CMD ["sleep", "infinity"]
