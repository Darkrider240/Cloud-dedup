# Serverless, Encryption-Aware Deduplication Pipeline with Anomaly Detection for AWS Cloud Storage

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![AWS Serverless](https://img.shields.io/badge/AWS-S3%20%7C%20DynamoDB%20%7C%20Lambda%20%7C%20KMS%20%7C%20CloudTrail-orange.svg)](https://aws.amazon.com/)
[![Cipher](https://img.shields.io/badge/Cipher-SPECK--128%2F128--CBC-green.svg)](https://en.wikipedia.org/wiki/Speck_(cipher))
[![Streamlit UI](https://img.shields.io/badge/Dashboard-Streamlit-red.svg)](https://streamlit.io/)

A university cloud architecture research and implementation project demonstrating a secure, serverless client-side deduplication pipeline tailored for edge/cloud environments. Combines NSA's lightweight **SPECK-128/128-CBC** block cipher with **Convergent Encryption**, content-defined chunking (CDC), atomic DynamoDB deduplication indexing, batched AWS KMS envelope key wrapping, and a pipeline-aware **CloudWatch/CloudTrail Anomaly Detector** with automated S3 versioning containment against ransomware attacks.

---

## Architecture Overview

```
                      +-------------------------------------------------------+
                      |                 Client Workstation / Edge             |
                      |                                                       |
                      |   [Input File] ---> [Gear-Hash CDC Chunking]          |
                      |                            |                          |
                      |                +-----------v------------+             |
                      |                | Convergent Key Deriv.  |             |
                      |                |  K = SHA-256(chunk)[:16] |            |
                      |                +-----------+------------+             |
                      |                            |                          |
                      |                +-----------v------------+             |
                      |                |   SPECK-128/128-CBC    |             |
                      |                |  Tag = SHA-256(Cipher) |             |
                      |                +-----------+------------+             |
                      +----------------------------|--------------------------+
                                                   |
                     +-----------------------------+-----------------------------+
                     | Atomic Claim (Conditional Put)                           |
                     v                                                           v
+------------------------------------------+        +------------------------------------------+
|         Amazon DynamoDB Table            |        |              Amazon S3 Bucket            |
|          (ChunkDedupIndex)               |        |         (drk-speck-dedup-storage)        |
|                                          |        |                                          |
| • Partition Key: chunk_hash (tag)        |        | • chunks/<tag>.bin (Uploaded IF NEW)     |
| • Attributes: s3_key, size, ref_count    |        | • manifests/<file>.json (KMS wrapped keys|
| • Deduplication: conditional check       |        |   + chunk tags + file SHA-256)           |
+------------------------------------------+        | • attack-sim/ (isolated security testing)|
                                                    +--------------------+---------------------+
                                                                         |
                                                            S3 Data Events (CloudTrail)
                                                                         |
                                                                         v
+------------------------------------------+        +--------------------+---------------------+
|        Amazon SNS / Incident Alert       |        |     CloudWatch Logs / EventBridge        |
|               (dedup-alerts)             |<-------+     (Lambda: dedup-anomaly-detector)     |
|                                          |        |                                          |
| • SMS / Email Notifications on HIGH      |        | • Scheduled every 5 minutes              |
| • Auto-Response: S3 Versioning Enabled   |        | • Scans 10-minute lookback window        |
+------------------------------------------+        +------------------------------------------+
```

---

## Key Features

1. **Lightweight SPECK-128/128-CBC Cipher**
   - Verified against NSA official test vectors (`test_speck_vectors.py`).
   - Pure Python implementation tailored for resource-constrained IoT/Edge nodes lacking hardware AES acceleration.
2. **Deterministic Convergent Encryption**
   - Content-derived key: $K = \text{SHA256}(\text{chunk})[:16]$.
   - Ciphertext-derived tag: $\text{Tag} = \text{SHA256}(\text{Ciphertext})$. Prevents key disclosure (fixed vulnerability where tag was derived from plaintext).
   - Identical plaintext chunks produce identical ciphertext tags across independent users, enabling **cross-user deduplication** with zero storage overhead for duplicates.
3. **Gear-Hash Content-Defined Chunking (CDC)**
   - Rolling hash cut-point detection isolates local edits and insertions.
   - Unlike fixed-size chunking, small file updates only invalidate local chunks, achieving 80–95%+ chunk reuse.
4. **AWS KMS Envelope Protection**
   - Chunk encryption keys are batched (up to 200 keys / 3,200 bytes per KMS call) and stored within an S3 manifest.
   - Whole-file integrity is validated against root SHA-256 upon restoration.
5. **Pipeline-Aware CloudTrail Anomaly Detector (v3)**
   - Distinguishes legitimate high-volume uploads from ransomware behaviors:
     - `bulk_delete` (HIGH): rapid object deletion.
     - `read_modify_write` (HIGH): in-place chunk overwrites violating immutability.
     - `config_tampering` (HIGH): suspension of bucket versioning or ACL modification.
     - `unexpected_prefix_write` (MEDIUM): writes outside `chunks/` or `manifests/`.
   - **Automated Incident Response**: Auto-enables S3 Bucket Versioning upon detecting HIGH-severity destruction events.
6. **Interactive Security Operations Center & Dashboard**
   - Streamlit-powered local SOC interface featuring Ingestion, Cryptographic Restore & Verification, Storage Analytics, Real-Time CloudWatch Threat Intel, and an Adversary Simulation Lab.

---

## Repository Structure

```
├── speck_cipher.py           # Pure-Python SPECK-128/128 block cipher (NSA specification)
├── dedup_core.py             # Gear-hash CDC chunking, key derivation, and encrypt/decrypt logic
├── dedup_client.py           # Production AWS client (upload, download, manifest, DynamoDB atomic claim)
├── anomaly_detector_v3.py    # Pipeline-aware CloudTrail event analysis & Lambda handler
├── lambda_dedup_trigger.py   # Event-driven S3 ObjectCreated Lambda verifying DynamoDB indexing
├── dashboard.py              # Interactive Streamlit GUI (SOC, analytics, restore, attack lab)
├── simulate_attack_v2.py     # Live AWS attack simulation (delete, rmw, copy, config, slow)
├── benchmark.py              # Storage efficiency & SPECK vs. AES micro-benchmarking
├── evaluate_detector.py      # Statistical evaluation of detector v2 vs. v3 (ROC, confusion matrix)
├── reset_storage.py          # Secure cleanup utility for test DynamoDB items and S3 objects/versions
├── test_speck_vectors.py     # NSA test vector validation suite
├── test_local_logic.py       # Offline sanity test for CDC chunking & convergent determinism
├── requirements.txt          # Python dependencies
└── README.md                 # Complete system documentation
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- AWS Account configured with credentials in `~/.aws/credentials` (IAM user with permissions for S3, DynamoDB, KMS, and CloudWatch Logs).
- Default region: `ap-south-1`.

### 1. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 2. Run Local Verification Tests

Verify the cryptographic implementation offline:

```powershell
# 1. Test SPECK-128/128 official NSA test vector
python test_speck_vectors.py

# 2. Test local Gear-hash CDC chunking and convergent encryption determinism
python test_local_logic.py
```

### 3. Launch the Streamlit Dashboard

Run the local web dashboard:

```powershell
python -m streamlit run dashboard.py
```

Once running, navigate to `http://localhost:8501` to access:
- **Upload & Dedup**: Ingest files, inspect chunk boundaries, and review space savings.
- **Restore & Verify**: Decrypt and verify root SHA-256 integrity tags.
- **Storage Analytics**: Real-time DynamoDB unique chunks vs. physical S3 footprint.
- **Incident Monitor (SOC)**: Live CloudWatch Logs Insights feed with threat classification.
- **Threat Simulation Lab**: Safely execute attack patterns under `attack-sim/`.
- **Convergent Dedup Demo**: Multi-user simulation demonstrating 0-byte duplicate storage.

---

## Command-Line Usage

```powershell
# Ingest and deduplicate a file
python dedup_client.py upload path/to/document.pdf

# Restore and cryptographically verify a file from S3 manifests
python dedup_client.py download document.pdf restored_document.pdf

# List stored manifests
python dedup_client.py list

# Display storage deduplication metrics
python dedup_client.py stats
```

---

## Evaluating the Detector & Running Benchmarks

### Benchmark Suite (`benchmark.py`)
Compares SPECK vs. pure-Python AES-128-CBC across text, binary, and mixed datasets with variable duplicate ratios:
```powershell
python benchmark.py
```
*Outputs: `results.csv`, `edit_results.csv`, and `benchmark_chart.png`.*

### Detector Evaluation (`evaluate_detector.py`)
Evaluates detection rules over 440 labeled synthetic CloudTrail windows:
```powershell
python evaluate_detector.py
```
*Outputs: `detector_results.csv` and `detector_chart.png`.*

| Detector Rule Set | Precision | Recall | F1 Score | False Positive Rate |
| :--- | :---: | :---: | :---: | :---: |
| **v2 Rules** (Put-Count Threshold) | 0.674 | 0.745 | 0.708 | 0.300 |
| **v3 Rules** (Pipeline-Aware Invariants) | **1.000** | **0.800** | **0.889** | **0.000** |

*Note: The slow-and-low attack (3 deletes) is intentionally below the delete threshold (5) to prevent false positives on legitimate administrative cleanup.*

---

## AWS Configuration Details

| Resource | Identifier / Configuration |
| :--- | :--- |
| **S3 Storage Bucket** | `drk-speck-dedup-storage` (`chunks/`, `manifests/`, `attack-sim/`) |
| **DynamoDB Index Table** | `ChunkDedupIndex` (Partition key: `chunk_hash` [String]) |
| **KMS Key Alias** | `alias/speck-dedup-key` |
| **S3 Trigger Lambda** | `dedup-chunk-trigger` (bound to `chunks/` ObjectCreated) |
| **Anomaly Detector Lambda** | `dedup-anomaly-detector` (Scheduled via EventBridge every 5 min) |
| **CloudTrail Log Group** | `aws-cloudtrail-logs-196893792193-55495899` |
| **SNS Alert Topic** | `dedup-alerts` |

---

## Security Considerations & Scope

- **Ciphertext-derived Tagging**: Deriving tags from ciphertext ensures that possession of the tag does not reveal the convergent key $K$.
- **Format-Agnostic Byte CDC**: The pipeline deduplicates at the byte stream level. Updates within identical file formats achieve high deduplication; cross-format identical text (e.g. DOCX vs. PDF) produces distinct binary representations.
- **Confirmation Attacks**: Convergent encryption inherently leaks file existence. Mitigating this via DupLESS-style OPRF key servers is identified as future work.

---

## License

This project is developed for educational and academic research purposes under the MIT License.
