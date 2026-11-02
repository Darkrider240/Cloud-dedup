"""
Anomaly Detector v3 (Lambda)

Pipeline-aware detection over CloudTrail S3 events delivered to CloudWatch Logs.

Why v3: v2 flagged ">20 PutObject in a window", which a perfectly legitimate
large upload triggers (every new chunk is a PutObject). v3 instead encodes what
THIS pipeline legitimately does:
  - the client only ever writes NEW objects under chunks/ and manifests/
  - the client never deletes objects
  - chunk objects are never read-then-rewritten (ciphertext is immutable)
Ransomware-style behaviour violates exactly these invariants.

Rules
  bulk_delete            HIGH    > DELETE_THRESHOLD deletes in the window
  read_modify_write      HIGH    > RMW_THRESHOLD distinct keys both read and rewritten
                                 (in-place encryption), manifests/ excluded
  config_tampering       HIGH    versioning suspended, bucket policy/ACL changed/removed
  unexpected_prefix_write MEDIUM > UNEXPECTED_PUT_THRESHOLD puts outside chunks/ manifests/
  bulk_read              LOW     > BULK_READ_THRESHOLD GetObjects (possible exfiltration)

Optional env vars (set in Lambda -> Configuration -> Environment variables):
  SNS_TOPIC_ARN   publish an alert email/SMS when anomalies fire
  AUTO_RESPOND    "true" -> on a HIGH data-destruction anomaly, enable S3
                  versioning on the bucket (non-destructive, makes deleted /
                  overwritten objects recoverable)

Clients are created lazily so analyze_events() can be imported and evaluated
offline without AWS.
"""

import os
import json
import time
from datetime import datetime, timedelta, timezone

LOG_GROUP_NAME = "aws-cloudtrail-logs-196893792193-55495899"
BUCKET_NAME = "drk-speck-dedup-storage"
WINDOW_MINUTES = 10

DEFAULT_CFG = {
    "delete_threshold": 5,
    "rmw_threshold": 5,
    "unexpected_put_threshold": 3,
    "bulk_read_threshold": 300,
    "allowed_prefixes": ("chunks/", "manifests/"),
}

F_NAME = "eventName"
F_KEY = "requestParameters.key"
F_VERS = "requestParameters.VersioningConfiguration.Status"
F_USER = "userIdentity.userName"
CONFIG_EVENTS = {"PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl"}
DELETE_EVENTS = {"DeleteObject", "DeleteObjects"}


def analyze_events(events, cfg=None):
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    deletes = 0
    gets, puts = set(), set()
    get_count = 0
    unexpected = 0
    config_flags = []

    for e in events:
        name = e.get(F_NAME, "")
        key = e.get(F_KEY, "")
        if name in DELETE_EVENTS:
            deletes += 1
        elif name == "GetObject":
            get_count += 1
            if key:
                gets.add(key)
        elif name == "PutObject":
            if key:
                puts.add(key)
            if not key.startswith(cfg["allowed_prefixes"]):
                unexpected += 1
        elif name in CONFIG_EVENTS:
            config_flags.append(f"{name} by {e.get(F_USER, 'unknown')}")
        elif name == "PutBucketVersioning" and e.get(F_VERS, "") == "Suspended":
            config_flags.append(f"PutBucketVersioning(Suspended) by {e.get(F_USER, 'unknown')}")

    rmw_keys = {k for k in (gets & puts) if not k.startswith("manifests/")}

    anomalies = []
    if deletes > cfg["delete_threshold"]:
        anomalies.append({"type": "bulk_delete", "severity": "HIGH",
                          "detail": f"{deletes} deletes in {WINDOW_MINUTES} min (threshold {cfg['delete_threshold']})"})
    if len(rmw_keys) > cfg["rmw_threshold"]:
        anomalies.append({"type": "read_modify_write", "severity": "HIGH",
                          "detail": f"{len(rmw_keys)} objects read then rewritten (threshold {cfg['rmw_threshold']})"})
    for flag in config_flags:
        anomalies.append({"type": "config_tampering", "severity": "HIGH", "detail": flag})
    if unexpected > cfg["unexpected_put_threshold"]:
        anomalies.append({"type": "unexpected_prefix_write", "severity": "MEDIUM",
                          "detail": f"{unexpected} writes outside {cfg['allowed_prefixes']} (threshold {cfg['unexpected_put_threshold']})"})
    if get_count > cfg["bulk_read_threshold"]:
        anomalies.append({"type": "bulk_read", "severity": "LOW",
                          "detail": f"{get_count} reads in {WINDOW_MINUTES} min (threshold {cfg['bulk_read_threshold']})"})

    return {"deletes": deletes, "puts": len(puts), "gets": get_count,
            "rmw_keys": len(rmw_keys), "unexpected_puts": unexpected, "anomalies": anomalies}


# ---------------- AWS-facing parts ----------------

def run_insights_query(start_time, end_time):
    import boto3
    logs = boto3.client("logs")
    query = f"""
    fields @timestamp, eventName, requestParameters.key, userIdentity.userName,
           requestParameters.VersioningConfiguration.Status
    | filter requestParameters.bucketName = "{BUCKET_NAME}"
    | sort @timestamp desc
    | limit 10000
    """
    qid = logs.start_query(logGroupName=LOG_GROUP_NAME, startTime=int(start_time.timestamp()),
                           endTime=int(end_time.timestamp()), queryString=query)["queryId"]
    result = {"status": "Running"}
    for _ in range(25):
        result = logs.get_query_results(queryId=qid)
        if result["status"] in ("Complete", "Failed", "Cancelled"):
            break
        time.sleep(1)
    if result["status"] != "Complete":
        raise RuntimeError(f"Insights query ended with status {result['status']}")
    return [{f["field"]: f["value"] for f in row} for row in result.get("results", [])]


def send_alert(anomalies, summary):
    topic = os.environ.get("SNS_TOPIC_ARN")
    if not topic:
        return False
    import boto3
    lines = [f"[{a['severity']}] {a['type']}: {a['detail']}" for a in anomalies]
    boto3.client("sns").publish(
        TopicArn=topic,
        Subject=f"S3 anomaly detected on {BUCKET_NAME}"[:100],
        Message="\n".join(lines) + f"\n\nWindow: {WINDOW_MINUTES} min   Summary: {json.dumps(summary)}")
    return True


def auto_respond(anomalies):
    if os.environ.get("AUTO_RESPOND", "").lower() != "true":
        return None
    if not any(a["severity"] == "HIGH" and a["type"] in ("bulk_delete", "read_modify_write") for a in anomalies):
        return None
    import boto3
    boto3.client("s3").put_bucket_versioning(
        Bucket=BUCKET_NAME, VersioningConfiguration={"Status": "Enabled"})
    return "S3 versioning enabled on bucket"


def lambda_handler(event, context):
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=WINDOW_MINUTES)
    events = run_insights_query(start, end)
    result = analyze_events(events)
    result["events_scanned"] = len(events)

    if result["anomalies"]:
        print("ANOMALY DETECTED:")
        print(json.dumps(result["anomalies"], indent=2))
        result["alert_sent"] = send_alert(result["anomalies"], {k: v for k, v in result.items() if k != "anomalies"})
        result["response"] = auto_respond(result["anomalies"])
        if result["response"]:
            print("AUTO-RESPONSE:", result["response"])
    else:
        print(f"No anomalies. {json.dumps({k: v for k, v in result.items() if k != 'anomalies'})}")

    return {"statusCode": 200, "body": json.dumps(result, default=str)}
