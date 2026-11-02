"""
Detector evaluation on labeled synthetic CloudTrail-style windows.

Each window = the list of S3 events in one 10-minute analysis window, using the
same field names the Lambda reads from CloudWatch Logs Insights. Windows are
generated from models of (a) what this pipeline legitimately does and (b)
ransomware-style behaviour, with randomised sizes. Ground-truth labels come
from the generator.

Compared:  v2 rules (put-count threshold)   vs   v3 rules (pipeline-aware)
Outputs:   detector_results.csv, detector_chart.png
Run:       python evaluate_detector.py
"""

import csv
import random
import uuid

from anomaly_detector_v3 import analyze_events, F_NAME, F_KEY, F_VERS, F_USER

R = random.Random(2026)
PER_SCENARIO = 40


def _tag():
    return uuid.UUID(int=R.getrandbits(128)).hex + uuid.UUID(int=R.getrandbits(128)).hex


def ev(name, key=None, **kw):
    e = {F_NAME: name}
    if key:
        e[F_KEY] = key
    e.update(kw)
    return e


# ---------------- benign scenarios (label 0) ----------------
def b_idle():
    return [ev("GetObject", f"manifests/f{R.randint(1,9)}.json") for _ in range(R.randint(0, 3))]

def b_upload():          # large uploads are the case v2 gets wrong
    n = R.randint(3, 160)
    return [ev("PutObject", f"chunks/{_tag()}.bin") for _ in range(n)] + [ev("PutObject", "manifests/file.json")]

def b_restore():
    n = R.randint(3, 160)
    return [ev("GetObject", f"chunks/{_tag()}.bin") for _ in range(n)] + [ev("GetObject", "manifests/file.json")]

def b_download_then_reupload():
    keys = [f"manifests/m{i}.json" for i in range(R.randint(1, 12))]
    return [ev("GetObject", k) for k in keys] + [ev("PutObject", k) for k in keys]

def b_admin_cleanup():
    return [ev("DeleteObject", f"manifests/old{i}.json") for i in range(R.randint(1, 4))]

def b_admin_enable_versioning():
    return [ev("PutBucketVersioning", **{F_VERS: "Enabled", F_USER: "admin"})]

# ---------------- attack scenarios (label 1) ----------------
def a_bulk_delete():
    return [ev("DeleteObject", f"chunks/{_tag()}.bin") for _ in range(R.randint(6, 60))]

def a_inplace_encrypt():
    keys = [f"chunks/{_tag()}.bin" for _ in range(R.randint(6, 60))]
    return [ev("GetObject", k) for k in keys] + [ev("PutObject", k) for k in keys]

def a_copy_encrypt_delete():
    n = R.randint(6, 40)
    ks = [f"chunks/{_tag()}.bin" for _ in range(n)]
    return ([ev("GetObject", k) for k in ks] +
            [ev("PutObject", f"enc/{_tag()}.locked") for _ in range(n)] +
            [ev("DeleteObject", k) for k in ks])

def a_config_tamper():
    pool = [lambda: ev("PutBucketVersioning", **{F_VERS: "Suspended", F_USER: "attacker"}),
            lambda: ev("PutBucketPolicy", **{F_USER: "attacker"}),
            lambda: ev("DeleteBucketPolicy", **{F_USER: "attacker"})]
    return [R.choice(pool)() for _ in range(R.randint(1, 2))]

def a_slow_low():        # evasion: stays under count thresholds
    return [ev("DeleteObject", f"chunks/{_tag()}.bin") for _ in range(R.randint(1, 4))]

BENIGN = [("idle", b_idle), ("large upload", b_upload), ("restore", b_restore),
          ("download + re-upload", b_download_then_reupload),
          ("admin cleanup (1-4 deletes)", b_admin_cleanup), ("admin enables versioning", b_admin_enable_versioning)]
ATTACK = [("bulk delete", a_bulk_delete), ("in-place encryption", a_inplace_encrypt),
          ("copy-encrypt-delete", a_copy_encrypt_delete), ("config tampering", a_config_tamper),
          ("slow-and-low deletes (evasion)", a_slow_low)]


# ---------------- v2 baseline rules ----------------
def detect_v2(events):
    d = sum(1 for e in events if e[F_NAME] in ("DeleteObject", "DeleteObjects"))
    p = sum(1 for e in events if e[F_NAME] == "PutObject")
    cfg = any(e[F_NAME] in ("PutBucketVersioning", "PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy") for e in events)
    return d > 5 or p > 20 or cfg


def detect_v3(events, cfg=None):
    return bool(analyze_events(events, cfg)["anomalies"])


def metrics(rows, detect):
    tp = fp = tn = fn = 0
    for label, events, _ in rows:
        flagged = detect(events)
        if label and flagged: tp += 1
        elif label: fn += 1
        elif flagged: fp += 1
        else: tn += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, precision=round(prec, 3), recall=round(rec, 3),
                F1=round(f1, 3), FPR=round(fp / (fp + tn), 3) if fp + tn else 0.0)


def main():
    rows = []
    for name, fn in BENIGN:
        rows += [(0, fn(), name) for _ in range(PER_SCENARIO)]
    for name, fn in ATTACK:
        rows += [(1, fn(), name) for _ in range(PER_SCENARIO)]
    print(f"Windows: {sum(1 for r in rows if r[0]==0)} benign, {sum(1 for r in rows if r[0]==1)} attack\n")

    results = {"v2 rules (put-count threshold)": metrics(rows, detect_v2),
               "v3 rules (pipeline-aware)": metrics(rows, detect_v3)}
    print(f"{'Detector':<32}{'TP':>4}{'FP':>4}{'TN':>5}{'FN':>4}{'Prec':>8}{'Recall':>8}{'F1':>7}{'FPR':>7}")
    for k, m in results.items():
        print(f"{k:<32}{m['TP']:>4}{m['FP']:>4}{m['TN']:>5}{m['FN']:>4}{m['precision']:>8}{m['recall']:>8}{m['F1']:>7}{m['FPR']:>7}")

    print("\nPer-scenario flag rate (fraction of windows flagged)")
    print(f"{'Scenario':<34}{'type':<8}{'v2':>7}{'v3':>7}")
    per = []
    for name, _ in BENIGN + ATTACK:
        sub = [r for r in rows if r[2] == name]
        lab = "attack" if sub[0][0] else "benign"
        f2 = sum(detect_v2(r[1]) for r in sub) / len(sub)
        f3 = sum(detect_v3(r[1]) for r in sub) / len(sub)
        per.append((name, lab, f2, f3))
        print(f"{name:<34}{lab:<8}{f2:>7.2f}{f3:>7.2f}")

    print("\nDelete-threshold sweep (v3)")
    sweep = []
    for t in range(0, 13):
        m = metrics(rows, lambda ev_, t=t: detect_v3(ev_, {"delete_threshold": t}))
        sweep.append((t, m["precision"], m["recall"], m["F1"]))
        print(f"  threshold={t:>2}  precision={m['precision']:.3f}  recall={m['recall']:.3f}  F1={m['F1']:.3f}")

    with open("detector_results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["detector", "TP", "FP", "TN", "FN", "precision", "recall", "F1", "FPR"])
        for k, m in results.items():
            w.writerow([k, m["TP"], m["FP"], m["TN"], m["FN"], m["precision"], m["recall"], m["F1"], m["FPR"]])
        w.writerow([]); w.writerow(["scenario", "type", "v2_flag_rate", "v3_flag_rate"])
        for r in per:
            w.writerow(r)
        w.writerow([]); w.writerow(["delete_threshold", "precision", "recall", "F1"])
        for r in sweep:
            w.writerow(r)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(1, 3, figsize=(18, 5))
    names = list(results)
    x = range(3)
    for i, k in enumerate(names):
        vals = [results[k]["precision"], results[k]["recall"], results[k]["F1"]]
        ax[0].bar([j + i * 0.38 for j in x], vals, 0.38, label=k)
    ax[0].set_xticks([j + 0.19 for j in x]); ax[0].set_xticklabels(["Precision", "Recall", "F1"])
    ax[0].set_ylim(0, 1.08); ax[0].set_title("Detector comparison"); ax[0].legend(fontsize=8); ax[0].grid(alpha=0.3, axis="y")

    labels = [p[0] for p in per]
    y = range(len(per))
    ax[1].barh([i + 0.2 for i in y], [p[2] for p in per], 0.38, label="v2")
    ax[1].barh([i - 0.2 for i in y], [p[3] for p in per], 0.38, label="v3")
    ax[1].set_yticks(list(y)); ax[1].set_yticklabels(labels, fontsize=8); ax[1].invert_yaxis()
    ax[1].axhline(len(BENIGN) - 0.5, color="grey", ls="--")
    ax[1].set_xlabel("Fraction of windows flagged"); ax[1].set_title("Per scenario (above line = benign)")
    ax[1].legend(); ax[1].grid(alpha=0.3, axis="x")

    ax[2].plot([s[0] for s in sweep], [s[1] for s in sweep], marker="o", label="Precision")
    ax[2].plot([s[0] for s in sweep], [s[2] for s in sweep], marker="s", label="Recall")
    ax[2].plot([s[0] for s in sweep], [s[3] for s in sweep], marker="^", label="F1")
    ax[2].set_xlabel("Delete threshold"); ax[2].set_title("Threshold sensitivity (v3)")
    ax[2].legend(); ax[2].grid(alpha=0.3)
    plt.tight_layout(); plt.savefig("detector_chart.png", dpi=150)
    print("\nSaved detector_results.csv, detector_chart.png")


if __name__ == "__main__":
    main()
