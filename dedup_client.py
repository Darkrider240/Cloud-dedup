"""
Encrypted Deduplication Client v2

Commands:
    python dedup_client.py upload <filepath>
    python dedup_client.py download <name> <output_path>
    python dedup_client.py list
    python dedup_client.py stats

How it works:
  upload   : split file into content-defined chunks -> convergent-encrypt each
             with SPECK -> atomically claim the chunk tag in DynamoDB
             (conditional put). If the claim succeeds the chunk is new and is
             uploaded to S3; if not, it is a duplicate and only ref_count is
             incremented. Chunk keys are wrapped with KMS (batched) and stored,
             with the ordered chunk list, in a per-file manifest in S3.
  download : read manifest -> unwrap keys with KMS -> fetch + decrypt chunks ->
             reassemble -> verify SHA-256 of the whole file.
"""

import sys
import os
import io
import json
import time
import base64
import hashlib

import boto3
from botocore.exceptions import ClientError

from dedup_core import cdc_chunks, encrypt_chunk, decrypt_chunk

# ---- CONFIG ----
S3_BUCKET = "drk-speck-dedup-storage"
DYNAMO_TABLE = "ChunkDedupIndex"
AWS_REGION = "ap-south-1"
KMS_KEY_ALIAS = "alias/speck-dedup-key"
# ----------------

CHUNK_PREFIX = "chunks/"          # Lambda trigger is bound to this prefix
MANIFEST_PREFIX = "manifests/"
KMS_BLOCK_KEYS = 200              # 200 x 16B = 3200B per KMS call (limit 4096B)

s3 = boto3.client("s3", region_name=AWS_REGION)
kms = boto3.client("kms", region_name=AWS_REGION)
table = boto3.resource("dynamodb", region_name=AWS_REGION).Table(DYNAMO_TABLE)


# ---------- KMS envelope: wrap/unwrap chunk keys in batches ----------
def wrap_keys(keys):
    blobs = []
    for i in range(0, len(keys), KMS_BLOCK_KEYS):
        block = b"".join(keys[i:i + KMS_BLOCK_KEYS])
        resp = kms.encrypt(KeyId=KMS_KEY_ALIAS, Plaintext=block)
        blobs.append(base64.b64encode(resp["CiphertextBlob"]).decode())
    return blobs


def unwrap_keys(blobs, total):
    raw = b""
    for b in blobs:
        raw += kms.decrypt(CiphertextBlob=base64.b64decode(b))["Plaintext"]
    return [raw[i * 16:(i + 1) * 16] for i in range(total)]


# ---------- Dedup index (atomic claim) ----------
def claim_chunk(tag: str, size: int) -> bool:
    """True if this call created the index entry (chunk is NEW)."""
    try:
        table.put_item(
            Item={"chunk_hash": tag, "s3_key": f"{CHUNK_PREFIX}{tag}.bin",
                  "size": size, "ref_count": 1},
            ConditionExpression="attribute_not_exists(chunk_hash)",
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            table.update_item(
                Key={"chunk_hash": tag},
                UpdateExpression="SET ref_count = ref_count + :one",
                ExpressionAttributeValues={":one": 1},
            )
            return False
        raise


def release_claim(tag: str):
    table.delete_item(Key={"chunk_hash": tag})


# ---------- Upload ----------
def upload_data(data: bytes, name: str):
    t0 = time.perf_counter()
    chunks = cdc_chunks(data)
    keys, entries = [], []
    chunk_table = []
    new_chunks = dup_chunks = 0
    new_bytes = 0

    for idx, chunk in enumerate(chunks):
        key, ct, tag = encrypt_chunk(chunk)
        keys.append(key)
        entries.append({"tag": tag, "len": len(chunk)})

        is_new = claim_chunk(tag, len(ct))
        if is_new:
            try:
                s3.put_object(Bucket=S3_BUCKET, Key=f"{CHUNK_PREFIX}{tag}.bin", Body=ct)
            except Exception:
                release_claim(tag)
                raise
            new_chunks += 1
            new_bytes += len(ct)
            print(f"  chunk {idx:>4}: NEW        {tag[:12]}...  {len(ct)} B")
            status = "NEW"
        else:
            dup_chunks += 1
            print(f"  chunk {idx:>4}: DUPLICATE  {tag[:12]}...")
            status = "DUPLICATE"

        chunk_table.append({
            "chunk_idx": idx,
            "tag": tag,
            "tag_short": tag[:12] + "...",
            "plain_len": len(chunk),
            "cipher_len": len(ct),
            "status": status,
        })

    manifest = {
        "name": name,
        "size": len(data),
        "file_sha256": hashlib.sha256(data).hexdigest(),
        "chunks": entries,
        "wrapped_keys": wrap_keys(keys),
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    s3.put_object(Bucket=S3_BUCKET, Key=f"{MANIFEST_PREFIX}{name}.json",
                  Body=json.dumps(manifest).encode())

    elapsed = time.perf_counter() - t0
    savings_pct = 100 * (1 - new_bytes / len(data)) if len(data) else 0.0

    print("\n--- Upload summary ---")
    print(f"File: {name}  ({len(data)} B)")
    print(f"Chunks: {len(chunks)}  new: {new_chunks}  duplicate: {dup_chunks}")
    print(f"Bytes stored this upload: {new_bytes}")
    if len(data):
        print(f"Savings vs. storing the file again: {savings_pct:.1f}%")
    print(f"Time: {elapsed:.2f}s")

    return {
        "name": name,
        "size": len(data),
        "file_sha256": manifest["file_sha256"],
        "chunks": chunk_table,
        "total_chunks": len(chunks),
        "new_chunks": new_chunks,
        "dup_chunks": dup_chunks,
        "new_bytes": new_bytes,
        "savings_pct": savings_pct,
        "elapsed_sec": elapsed,
    }


def upload_file(filepath: str = None, data: bytes = None, filename: str = None):
    if data is None and filepath is not None:
        filename = filename or os.path.basename(filepath)
        with open(filepath, "rb") as f:
            data = f.read()
    elif data is not None and filename is None:
        filename = "unnamed.bin"
    elif data is None and filepath is None:
        raise ValueError("Must provide either filepath or data")

    return upload_data(data, filename)


# ---------- Download / restore ----------
def download_file(name: str, out_path: str = None):
    t0 = time.perf_counter()
    obj = s3.get_object(Bucket=S3_BUCKET, Key=f"{MANIFEST_PREFIX}{name}.json")
    manifest = json.loads(obj["Body"].read())

    entries = manifest["chunks"]
    keys = unwrap_keys(manifest["wrapped_keys"], len(entries))

    out = io.BytesIO()
    for e, key in zip(entries, keys):
        ct = s3.get_object(Bucket=S3_BUCKET, Key=f"{CHUNK_PREFIX}{e['tag']}.bin")["Body"].read()
        pt = decrypt_chunk(ct, key)
        if len(pt) != e["len"]:
            raise ValueError(f"Chunk {e['tag'][:12]} length mismatch")
        out.write(pt)

    data = out.getvalue()
    computed_sha256 = hashlib.sha256(data).hexdigest()
    ok = computed_sha256 == manifest["file_sha256"]

    if out_path:
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"Restored {name} -> {out_path} ({len(data)} B) in {time.perf_counter() - t0:.2f}s")
    else:
        print(f"Restored {name} in memory ({len(data)} B) in {time.perf_counter() - t0:.2f}s")

    print("Integrity check (SHA-256 vs original):", "PASS" if ok else "FAIL")
    if not ok and out_path:
        sys.exit(2)

    return {
        "name": name,
        "size": len(data),
        "chunks_count": len(entries),
        "file_sha256": manifest["file_sha256"],
        "computed_sha256": computed_sha256,
        "integrity": "PASS" if ok else "FAIL",
        "elapsed_sec": time.perf_counter() - t0,
        "data": data,
    }


# ---------- List / stats ----------
def _list_manifests():
    items = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=MANIFEST_PREFIX):
        for o in page.get("Contents", []):
            m = json.loads(s3.get_object(Bucket=S3_BUCKET, Key=o["Key"])["Body"].read())
            items.append(m)
    return items


def list_files():
    manifests = _list_manifests()
    for m in manifests:
        print(f"{m['name']:<30} {m['size']:>10} B   {len(m['chunks']):>4} chunks   {m['created']}")
    return manifests


def get_stats():
    manifests = _list_manifests()
    logical = sum(m["size"] for m in manifests)

    stored, unique, refs = 0, 0, 0
    scan = table.scan()
    while True:
        for it in scan["Items"]:
            unique += 1
            stored += int(it.get("size", 0))
            refs += int(it.get("ref_count", 0))
        if "LastEvaluatedKey" not in scan:
            break
        scan = table.scan(ExclusiveStartKey=scan["LastEvaluatedKey"])

    dedup_ratio = (logical / max(stored, 1)) if stored > 0 else 1.0
    space_saved = (100 * (1 - stored / logical)) if logical > 0 else 0.0

    return {
        "files_count": len(manifests),
        "logical_bytes": logical,
        "unique_chunks": unique,
        "chunk_refs": refs,
        "physical_bytes": stored,
        "dedup_ratio": dedup_ratio,
        "space_saved_pct": space_saved,
        "manifests": manifests,
    }


def show_stats():
    stats = get_stats()
    manifests = stats["manifests"]
    logical = stats["logical_bytes"]
    unique = stats["unique_chunks"]
    refs = stats["chunk_refs"]
    stored = stats["physical_bytes"]

    print(f"Files: {len(manifests)}   Logical size: {logical} B")
    print(f"Unique chunks: {unique}   Chunk references: {refs}   Physical size: {stored} B")
    if logical:
        print(f"Dedup ratio: {stats['dedup_ratio']:.2f}x   Space saved: {stats['space_saved_pct']:.1f}%")
    return stats


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "upload":
        if not os.path.exists(args[1]):
            sys.exit(f"File not found: {args[1]}")
        upload_file(args[1])
    elif len(args) == 3 and args[0] == "download":
        download_file(args[1], args[2])
    elif args == ["list"]:
        list_files()
    elif args == ["stats"]:
        show_stats()
    else:
        print(__doc__)
