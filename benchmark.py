"""
Evaluation benchmark (runs locally, no AWS needed).

Experiment 1 - Storage efficiency and cost of confidentiality
    Datasets: text / binary / mixed, each at 0/25/50/75 % exact-duplicate files.
    Schemes compared:
      A. No dedup (encrypt everything)           -> naive secure baseline
      B. Plaintext dedup (INSECURE)              -> upper bound on savings
      C. Convergent encryption + AES-128-CBC     -> standard cipher baseline
      D. Convergent encryption + SPECK-128/128   -> proposed scheme
    Metrics: dedup ratio, space saved %, encrypt/decrypt throughput.

Experiment 2 - Chunking: content-defined vs fixed-size, after a small
    insertion near the start of a file (fraction of chunks still reusable).

Experiment 3 - Cipher micro-benchmark: SPECK vs AES, both pure-Python.

Outputs: results.csv, edit_results.csv, benchmark_chart.png
Install:  pip install pyaes matplotlib
"""

import csv
import hashlib
import random
import time

import pyaes

from speck_cipher import speck_encrypt, speck_decrypt
from dedup_core import cdc_chunks, fixed_chunks, derive_key, tag_of

N_FILES = 16
FILE_SIZE = 48 * 1024
DUP_LEVELS = [0.0, 0.25, 0.50, 0.75]
KINDS = ["text", "binary", "mixed"]
SEED = 42

# ---------------- AES-128-CBC (pure Python, same mode/IV/padding as SPECK) ----------------

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    enc = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv=b"\x00" * 16))
    return enc.feed(data) + enc.feed()


def aes_decrypt(ct: bytes, key: bytes) -> bytes:
    dec = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, iv=b"\x00" * 16))
    return dec.feed(ct) + dec.feed()


# ---------------- Dataset generation ----------------

_VOCAB = None

def _text_file(rng, size):
    global _VOCAB
    if _VOCAB is None:
        v = random.Random(7)
        letters = "abcdefghijklmnopqrstuvwxyz"
        _VOCAB = ["".join(v.choice(letters) for _ in range(v.randint(3, 9))) for _ in range(3000)]
    out, n = [], 0
    while n < size:
        w = rng.choice(_VOCAB)
        out.append(w)
        n += len(w) + 1
    return (" ".join(out)).encode()[:size]


def _binary_file(rng, size):
    return rng.getrandbits(size * 8).to_bytes(size, "big")


def make_dataset(kind, dup_frac, seed=SEED):
    rng = random.Random(seed)
    n_dup = round(N_FILES * dup_frac)
    n_unique = N_FILES - n_dup
    uniques = []
    for i in range(n_unique):
        k = kind if kind != "mixed" else ("text" if i % 2 == 0 else "binary")
        uniques.append(_text_file(rng, FILE_SIZE) if k == "text" else _binary_file(rng, FILE_SIZE))
    files = list(uniques)
    for _ in range(n_dup):
        files.append(rng.choice(uniques))
    rng.shuffle(files)
    return files


# ---------------- Experiment 1 ----------------

def padded_len(n):
    return (n // 16 + 1) * 16


def run_scheme(files, scheme):
    logical = sum(len(f) for f in files)
    enc_time = dec_time = 0.0
    stored = 0
    seen = {}

    for f in files:
        chunks = cdc_chunks(f)
        for c in chunks:
            if scheme == "no_dedup":
                stored += padded_len(len(c))            # every chunk stored, encrypted
            elif scheme == "plain_dedup":
                t0 = time.perf_counter()
                tag = hashlib.sha256(c).hexdigest()
                enc_time += time.perf_counter() - t0
                if tag not in seen:
                    seen[tag] = len(c)
                    stored += len(c)                      # stored in the clear
            else:
                enc = speck_encrypt if scheme == "conv_speck" else aes_encrypt
                key = derive_key(c)
                t0 = time.perf_counter()
                ct = enc(c, key)
                enc_time += time.perf_counter() - t0
                tag = tag_of(ct)
                if tag not in seen:
                    seen[tag] = (ct, key)
                    stored += len(ct)

    if scheme in ("conv_speck", "conv_aes"):
        dec = speck_decrypt if scheme == "conv_speck" else aes_decrypt
        t0 = time.perf_counter()
        for ct, key in seen.values():
            dec(ct, key)
        dec_time = time.perf_counter() - t0
        dec_bytes = sum(len(ct) for ct, _ in seen.values())
    else:
        dec_bytes = 0

    return {
        "logical_bytes": logical,
        "stored_bytes": stored,
        "dedup_ratio": round(logical / stored, 3),
        "space_saved_pct": round(100 * (1 - stored / logical), 1),
        "enc_s": round(enc_time, 3),
        "enc_MBps": round(logical / enc_time / 1e6, 3) if enc_time and scheme.startswith("conv") else None,
        "dec_MBps": round(dec_bytes / dec_time / 1e6, 3) if dec_time else None,
    }


SCHEMES = [
    ("no_dedup", "A. No dedup (encrypt all)"),
    ("plain_dedup", "B. Plaintext dedup (insecure)"),
    ("conv_aes", "C. Convergent + AES-128"),
    ("conv_speck", "D. Convergent + SPECK-128 (proposed)"),
]


def experiment1():
    rows = []
    for kind in KINDS:
        for dup in DUP_LEVELS:
            files = make_dataset(kind, dup)
            for key, label in SCHEMES:
                r = run_scheme(files, key)
                r.update(dataset=kind, dup_pct=int(dup * 100), scheme=label)
                rows.append(r)
                print(f"{kind:<7} dup={int(dup*100):>2}%  {label:<38} saved={r['space_saved_pct']:>6}%  "
                      f"ratio={r['dedup_ratio']:>5}  enc={r['enc_MBps']}")
    return rows


# ---------------- Experiment 2 ----------------

def experiment2():
    rng = random.Random(99)
    base = _binary_file(rng, 256 * 1024)
    edited = base[:1000] + b"<<INSERTED 100 BYTES OF NEW CONTENT>>" * 3 + base[1000:]   # insertion near start
    rows = []
    for name, fn in [("Fixed-size (8 KB)", fixed_chunks), ("Content-defined (Gear)", cdc_chunks)]:
        a = {hashlib.sha256(c).hexdigest() for c in fn(base)}
        b_chunks = fn(edited)
        b = [hashlib.sha256(c).hexdigest() for c in b_chunks]
        reused = sum(1 for h in b if h in a)
        rows.append({"chunking": name, "chunks_in_edited": len(b),
                     "reused": reused, "reuse_pct": round(100 * reused / len(b), 1)})
        print(f"{name:<24} reused {reused}/{len(b)} chunks ({rows[-1]['reuse_pct']}%) after small insertion")
    return rows


# ---------------- Experiment 3 ----------------

def experiment3():
    rng = random.Random(5)
    data = _binary_file(rng, 256 * 1024)
    key = bytes(range(16))
    out = {}
    for name, enc, dec in [("SPECK-128/128", speck_encrypt, speck_decrypt), ("AES-128", aes_encrypt, aes_decrypt)]:
        best_e = best_d = 1e9
        for _ in range(3):
            t0 = time.perf_counter(); ct = enc(data, key); best_e = min(best_e, time.perf_counter() - t0)
            t0 = time.perf_counter(); dec(ct, key); best_d = min(best_d, time.perf_counter() - t0)
        out[name] = (len(data) / best_e / 1e6, len(data) / best_d / 1e6)
        print(f"{name:<14} encrypt {out[name][0]:.3f} MB/s   decrypt {out[name][1]:.3f} MB/s")
    return out


# ---------------- Chart ----------------

def make_chart(rows, edit_rows, cipher):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(1, 3, figsize=(17, 4.8))

    mixed = [r for r in rows if r["dataset"] == "mixed"]
    for key, label in SCHEMES:
        pts = [(r["dup_pct"], r["space_saved_pct"]) for r in mixed if r["scheme"] == label]
        ax[0].plot(*zip(*pts), marker="o", label=label)
    ax[0].set_title("Space saved vs. duplicate content (mixed data)")
    ax[0].set_xlabel("Duplicate files (%)"); ax[0].set_ylabel("Space saved (%)")
    ax[0].legend(fontsize=7); ax[0].grid(alpha=0.3)

    names = list(cipher)
    w = 0.35
    ax[1].bar([i - w / 2 for i in range(2)], [cipher[n][0] for n in names], w, label="Encrypt")
    ax[1].bar([i + w / 2 for i in range(2)], [cipher[n][1] for n in names], w, label="Decrypt")
    ax[1].set_xticks(range(2)); ax[1].set_xticklabels(names)
    ax[1].set_ylabel("Throughput (MB/s)"); ax[1].set_title("Cipher throughput (pure Python)")
    ax[1].legend(); ax[1].grid(alpha=0.3, axis="y")

    ax[2].bar([r["chunking"] for r in edit_rows], [r["reuse_pct"] for r in edit_rows], color=["#c0504d", "#4f81bd"])
    ax[2].set_ylabel("Chunks reused (%)"); ax[2].set_ylim(0, 105)
    ax[2].set_title("Reuse after small insertion in file")
    for i, r in enumerate(edit_rows):
        ax[2].text(i, r["reuse_pct"] + 2, f"{r['reuse_pct']}%", ha="center")

    plt.tight_layout()
    plt.savefig("benchmark_chart.png", dpi=150)
    print("Saved benchmark_chart.png")


if __name__ == "__main__":
    print("=== Experiment 1: storage efficiency ===")
    rows = experiment1()
    with open("results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["dataset", "dup_pct", "scheme", "logical_bytes", "stored_bytes",
                                          "dedup_ratio", "space_saved_pct", "enc_s", "enc_MBps", "dec_MBps"])
        w.writeheader(); w.writerows(rows)

    print("\n=== Experiment 2: chunking strategy ===")
    edit_rows = experiment2()
    with open("edit_results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["chunking", "chunks_in_edited", "reused", "reuse_pct"])
        w.writeheader(); w.writerows(edit_rows)

    print("\n=== Experiment 3: cipher throughput ===")
    cipher = experiment3()

    make_chart(rows, edit_rows, cipher)
    print("Saved results.csv, edit_results.csv")
