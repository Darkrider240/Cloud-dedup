"""
Clears ALL test data: every object in the project bucket's chunks/ and
manifests/ prefixes, and every item in the DynamoDB dedup index.
Run once before using dedup_client.py v2, so old entries (which used the
plaintext hash as identifier) don't mix with new ones.
Does NOT touch the KMS key, trail, or Lambdas.
"""
import boto3

S3_BUCKET = "drk-speck-dedup-storage"
DYNAMO_TABLE = "ChunkDedupIndex"
REGION = "ap-south-1"

if input(f"Delete ALL chunks/manifests in {S3_BUCKET} and ALL items in {DYNAMO_TABLE}? Type 'yes': ") != "yes":
    raise SystemExit("Aborted.")

s3 = boto3.client("s3", region_name=REGION)
n = 0
for prefix in ("chunks/", "manifests/", "attack-sim/"):
    # Delete versioned objects and delete markers if versioning is/was active
    try:
        ver_paginator = s3.get_paginator("list_object_versions")
        for page in ver_paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix):
            to_delete = []
            for v in page.get("Versions", []):
                to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for dm in page.get("DeleteMarkers", []):
                to_delete.append({"Key": dm["Key"], "VersionId": dm["VersionId"]})
            if to_delete:
                s3.delete_objects(Bucket=S3_BUCKET, Delete={"Objects": to_delete})
                n += len(to_delete)
    except Exception:
        # Fallback to standard list_objects_v2 if list_object_versions is not supported
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=S3_BUCKET, Prefix=prefix):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=S3_BUCKET, Delete={"Objects": objs})
                n += len(objs)
print(f"Deleted {n} S3 objects/versions")

table = boto3.resource("dynamodb", region_name=REGION).Table(DYNAMO_TABLE)
m = 0
scan = table.scan(ProjectionExpression="chunk_hash")
while True:
    with table.batch_writer() as bw:
        for it in scan["Items"]:
            bw.delete_item(Key={"chunk_hash": it["chunk_hash"]}); m += 1
    if "LastEvaluatedKey" not in scan:
        break
    scan = table.scan(ProjectionExpression="chunk_hash", ExclusiveStartKey=scan["LastEvaluatedKey"])
print(f"Deleted {m} DynamoDB items")
