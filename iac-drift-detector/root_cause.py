"""
Root-cause attribution for drift — drift_check.py originally only answered
"what changed" (template said 128, live says 256). CloudTrail already
recorded WHO changed it and WHEN; this correlates a detected drift to the
actual API call that caused it instead of leaving that as a follow-up
question for whoever reads the report.

Best-effort by design: CloudTrail's `lookup_events` only covers the last 90
days regardless of how far back an S3-archived trail goes, and matches a
resource by checking whether its identifier appears anywhere in the raw
event JSON (CloudTrail doesn't expose a single reliable "ResourceId" field
across every service's event shape) — good enough to answer "who touched
this Lambda's config last week", not a guaranteed audit-grade chain of
custody.

A real bug lived here until live testing caught it: Lambda's CloudTrail
EventName isn't the plain API name you'd expect from the docs — it's
suffixed with the API version, e.g. "UpdateFunctionConfiguration20150331v2"
— so an exact-match lookup on "UpdateFunctionConfiguration" silently found
nothing, EVER, even for a change that had just happened and was sitting
right there in Event history. Fixed by looking up events by EventSource
(the service endpoint, which isn't versioned) and matching the event name
with startswith() instead of equality, so a versioned suffix on any
service doesn't quietly break the match again.
"""
import json
from datetime import datetime, timedelta, timezone

# Which CloudTrail event source + event-name prefix(es) could plausibly
# cause drift in each resource kind this tool already tracks. Prefixes, not
# exact names, because at least one service (Lambda) suffixes its real
# CloudTrail EventName with an API version.
RESOURCE_EVENTS = {
    "Lambda": ("lambda.amazonaws.com", ("UpdateFunctionConfiguration", "UpdateFunctionCode")),
    "API Gateway stage": ("apigateway.amazonaws.com", ("UpdateStage",)),
    "DynamoDB table": ("dynamodb.amazonaws.com", ("UpdateTable",)),
    "WAF rate rule": ("wafv2.amazonaws.com", ("UpdateWebACL",)),
}


def find_root_cause(cloudtrail, resource_kind, resource_identifier, lookback_days=90):
    """Returns {"username", "event_time", "event_name"} for the most recent
    matching event within the lookback window, or None if nothing was found
    (either no matching event happened, or it aged out of CloudTrail's
    90-day lookup_events retention)."""
    entry = RESOURCE_EVENTS.get(resource_kind)
    if not entry:
        return None
    event_source, name_prefixes = entry

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=lookback_days)
    candidates = []

    try:
        paginator = cloudtrail.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": event_source}],
            StartTime=start,
            EndTime=end,
        ):
            for event in page["Events"]:
                if not event["EventName"].startswith(name_prefixes):
                    continue
                raw = event.get("CloudTrailEvent", "{}")
                if resource_identifier.lower() not in raw.lower():
                    continue
                username = event.get("Username", "unknown")
                try:
                    user_identity = json.loads(raw).get("userIdentity", {})
                    username = user_identity.get("userName") or user_identity.get("arn", username)
                except (json.JSONDecodeError, AttributeError):
                    pass
                candidates.append((event["EventTime"], username, event["EventName"]))
    except Exception:
        return None

    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0], reverse=True)
    event_time, username, event_name = candidates[0]
    return {"username": username, "event_time": event_time.isoformat(), "event_name": event_name}
