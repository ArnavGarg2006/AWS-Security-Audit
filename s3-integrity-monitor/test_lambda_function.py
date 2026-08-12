import os
from unittest.mock import MagicMock

os.environ["TABLE_NAME"] = "test-table"
os.environ["TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:test-topic"

import lambda_function as lf  # noqa: E402


def make_event(event_name, bucket="test-bucket", key="AWSLogs/123/CloudTrail/file.json.gz", etag="abc123"):
    return {
        "Records": [{
            "eventName": event_name,
            "eventTime": "2026-08-13T00:00:00.000Z",
            "s3": {"bucket": {"name": bucket}, "object": {"key": key, "eTag": etag}},
        }]
    }


def setup_function():
    lf.table = MagicMock()
    lf.sns = MagicMock()


def test_new_object_recorded_without_alert():
    lf.table.get_item.return_value = {}
    lf.handler(make_event("ObjectCreated:Put"), None)

    lf.table.put_item.assert_called_once()
    lf.sns.publish.assert_not_called()


def test_unchanged_reupload_is_a_noop():
    lf.table.get_item.return_value = {"Item": {"etag": "abc123"}}
    lf.handler(make_event("ObjectCreated:Put", etag="abc123"), None)

    lf.table.put_item.assert_not_called()
    lf.table.update_item.assert_not_called()
    lf.sns.publish.assert_not_called()


def test_changed_etag_flags_modification_and_alerts():
    lf.table.get_item.return_value = {"Item": {"etag": "old-etag"}}
    lf.handler(make_event("ObjectCreated:Put", etag="new-etag"), None)

    lf.table.update_item.assert_called_once()
    lf.sns.publish.assert_called_once()
    args = lf.sns.publish.call_args.kwargs
    assert "HIGH" in args["Subject"]
    assert "overwritten" in args["Message"].lower()


def test_deletion_always_alerts_critical():
    lf.table.get_item.return_value = {"Item": {"etag": "abc123"}}
    lf.handler(make_event("ObjectRemoved:Delete"), None)

    lf.table.update_item.assert_called_once()
    lf.sns.publish.assert_called_once()
    args = lf.sns.publish.call_args.kwargs
    assert "CRITICAL" in args["Subject"]
    assert "deleted" in args["Message"].lower()


def test_deletion_of_untracked_object_still_alerts():
    lf.table.get_item.return_value = {}
    lf.handler(make_event("ObjectRemoved:Delete"), None)

    lf.sns.publish.assert_called_once()


def test_unhandled_event_type_is_ignored():
    event = make_event("ObjectRestore:Completed")
    lf.handler(event, None)

    lf.table.put_item.assert_not_called()
    lf.table.update_item.assert_not_called()
    lf.sns.publish.assert_not_called()


def test_multiple_records_in_one_event():
    lf.table.get_item.return_value = {}
    event = {"Records": [
        make_event("ObjectCreated:Put", key="file1.json")["Records"][0],
        make_event("ObjectRemoved:Delete", key="file2.json")["Records"][0],
    ]}
    lf.handler(event, None)

    assert lf.table.put_item.call_count == 1
    assert lf.table.update_item.call_count == 1
    assert lf.sns.publish.call_count == 1  # only the deletion alerts
