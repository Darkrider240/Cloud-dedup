"""
Live attack simulator (real AWS). Works only under the attack-sim/ prefix, so it
never touches your real chunks/ or manifests/.

    python simulate_attack_v2.py delete    # bulk delete
    python simulate_attack_v2.py rmw       # in-place "encryption": read + overwrite many objects
    python simulate_attack_v2.py copy      # read -> write encrypted copy -> delete original
    python simulate_attack_v2.py config    # suspend versioning (config tampering)
    python simulate_attack_v2.py slow      # 3 deletes only (evasion case, expected NOT detected)

Then wait ~5 min for CloudTrail -> CloudWatch delivery and the next detector run.
"""
import sys, uuid, boto3

BUCKET = "drk-speck-dedup-storage"
REGION = "ap-south-1"
s3 = boto3.client("s3", region_name=REGION)


def seed(n):
    keys = []
    for _ in range(n):
        k = f"attack-sim/victim-{uuid.uuid4().hex[:8]}.bin"
        s3.put_object(Bucket=BUCKET, Key=k, Body=b"victim data " * 20)
        keys.append(k)
    return keys


def run(mode):
    if mode == "delete":
        ks = seed(9)
        for k in ks: s3.delete_object(Bucket=BUCKET, Key=k)
        msg = "9 PutObject + 9 DeleteObject issued under attack-sim/"
    elif mode == "rmw":
        ks = seed(9)
        for k in ks:
            body = s3.get_object(Bucket=BUCKET, Key=k)["Body"].read()
            s3.put_object(Bucket=BUCKET, Key=k, Body=bytes(b ^ 0x5A for b in body))   # fake in-place encryption
        msg = "9 objects read and overwritten in place under attack-sim/"
    elif mode == "copy":
        ks = seed(9)
        for k in ks:
            body = s3.get_object(Bucket=BUCKET, Key=k)["Body"].read()
            s3.put_object(Bucket=BUCKET, Key=k.replace("victim", "locked") + ".enc", Body=body[::-1])
            s3.delete_object(Bucket=BUCKET, Key=k)
        msg = "9 objects: read -> encrypted copy written -> original deleted under attack-sim/"
    elif mode == "config":
        s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Suspended"})
        msg = "Bucket versioning set to Suspended"
    elif mode == "slow":
        ks = seed(3)
        for k in ks: s3.delete_object(Bucket=BUCKET, Key=k)
        msg = "3 deletes only (below threshold, evasion simulation)"
    else:
        sys.exit(__doc__)
    print(msg)
    return msg


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    run(sys.argv[1])
