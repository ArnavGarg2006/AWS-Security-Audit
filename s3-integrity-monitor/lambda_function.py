"""
S3 file integrity monitor.

Triggered by S3 Event Notifications (ObjectCreated:*, ObjectRemoved:*) on a
bucket you care about the contents of not changing unexpectedly — the
canonical case being a CloudTrail log bucket, where a modified or deleted
object is a strong signal someone is covering their tracks.

Behavior:
  - New object (key not seen before)         -> recorded, INFO, no alert.
  - Existing object, ETag changed (overwrite) -> recorded, HIGH,  SNS alert.
  - Object deleted                            -> recorded, CRITICAL, SNS alert.

State lives in DynamoDB (pk=bucket, sk=key) so overwrite/delete detection
works across cold starts and concurrent invocations.
"""
import json
import os
from datetime import datetime, timezone

import boto3

TABLE_NAME = os.environ["TABLE_NAME"]
TOPIC_ARN = os.environ["TOPIC_ARN"]

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(TABLE_NAME)
sns = boto3.client("sns")


def log(level, message, **meta):
    print(json.dumps({"level": level, "message": message, "timestamp": datetime.now(timezone.utc).isoformat(), **meta}))


def notify(subject, body):
    try:
        sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=body)
    except Exception as e:  # noqa: BLE001 - never let a notification failure break processing
        log("error", "SNS publish failed", error=str(e))


def handle_created(bucket, key, etag, event_time):
    existing = table.get_item(Key={"pk": bucket, "sk": key}).get("Item")

    if existing is None:
        table.put_item(Item={
            "pk": bucket, "sk": key, "etag": etag,
            "lastEventType": "CREATED", "lastEventTime": event_time,
            "firstSeenTime": event_time,
        })
        log("info", "New object recorded", bucket=bucket, key=key)
        return

    if existing.get("etag") != etag:
        table.update_item(
            Key={"pk": bucket, "sk": key},
            UpdateExpression="SET etag = :e, lastEventType = :t, lastEventTime = :ts",
            ExpressionAttributeValues={":e": etag, ":t": "MODIFIED", ":ts": event_time},
        )
        log("warn", "Object modified (ETag changed)", bucket=bucket, key=key,
            old_etag=existing.get("etag"), new_etag=etag)
        notify(
            f"[HIGH] S3 object modified: {key}",
            f"Bucket: {bucket}\nKey: {key}\nTime: {event_time}\n"
            f"Previous ETag: {existing.get('etag')}\nNew ETag: {etag}\n\n"
            "An existing object was overwritten. For an append-only log bucket "
            "(e.g. CloudTrail), this is unexpected and worth investigating.",
        )
    # else: duplicate event for an unchanged object, nothing to do.


def handle_removed(bucket, key, event_time):
    existing = table.get_item(Key={"pk": bucket, "sk": key}).get("Item")

    table.update_item(
        Key={"pk": bucket, "sk": key},
        UpdateExpression="SET lastEventType = :t, lastEventTime = :ts",
        ExpressionAttributeValues={":t": "DELETED", ":ts": event_time},
    )
    log("error", "Object deleted", bucket=bucket, key=key)
    notify(
        f"[CRITICAL] S3 object deleted: {key}",
        f"Bucket: {bucket}\nKey: {key}\nTime: {event_time}\n"
        f"Last known ETag: {(existing or {}).get('etag', 'unknown')}\n\n"
        "An object was deleted. For an append-only log bucket, objects should "
        "never be deleted through normal operation — treat this as a potential "
        "attempt to destroy evidence until proven otherwise.",
    )


def handler(event, context):
    for record in event.get("Records", []):
        event_name = record.get("eventName", "")
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]
        etag = record["s3"]["object"].get("eTag", "")
        event_time = record.get("eventTime", datetime.now(timezone.utc).isoformat())

        if event_name.startswith("ObjectCreated:"):
            handle_created(bucket, key, etag, event_time)
        elif event_name.startswith("ObjectRemoved:"):
            handle_removed(bucket, key, event_time)
        else:
            log("info", "Ignoring unhandled event type", eventName=event_name, bucket=bucket, key=key)

    return {"statusCode": 200}
