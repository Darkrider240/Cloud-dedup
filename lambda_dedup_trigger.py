"""
Lambda function: triggered on S3 ObjectCreated events in your bucket's
chunks/ prefix. Confirms the chunk is properly indexed in DynamoDB and
logs event-driven pipeline activity to CloudWatch.

This is the "event-driven" piece of your architecture — it proves the
dedup pipeline reacts automatically to uploads rather than relying on
a batch job, which is the core "Solution Architecture" claim in your
report.

Deploy this as the function body in AWS Lambda console (Day 4).
"""

import json
import boto3
import urllib.parse

DYNAMO_TABLE = "ChunkDedupIndex"

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(DYNAMO_TABLE)


def lambda_handler(event, context):
    results = []

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        size = record["s3"]["object"].get("size", 0)
        event_time = record.get("eventTime")

        print(f"New object event: bucket={bucket} key={key} size={size} time={event_time}")

        # chunk hash is embedded in the S3 key as chunks/<hash>.bin
        if key.startswith("chunks/") and key.endswith(".bin"):
            chunk_hash = key[len("chunks/"):-len(".bin")]

            # confirm this hash is registered in DynamoDB (it should be,
            # since dedup_client.py writes to DynamoDB before/along with
            # the S3 upload) -- this acts as a consistency check
            resp = table.get_item(Key={"chunk_hash": chunk_hash})
            indexed = "Item" in resp

            log_entry = {
                "event": "chunk_upload_confirmed",
                "chunk_hash": chunk_hash,
                "s3_key": key,
                "size_bytes": size,
                "indexed_in_dynamodb": indexed,
            }
            print(json.dumps(log_entry))
            results.append(log_entry)

            if not indexed:
                # this would be unusual -- flag it as a pipeline
                # inconsistency worth investigating
                print(f"WARNING: chunk {chunk_hash} uploaded to S3 but not found in DynamoDB index")

    return {
        "statusCode": 200,
        "body": json.dumps({"processed": len(results), "details": results})
    }