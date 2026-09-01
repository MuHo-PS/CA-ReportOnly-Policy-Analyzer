"""Pure aggregation logic for CA report-only sign-in analysis.

No network I/O lives in this module. Every function here takes plain
dicts/lists already fetched by graph_client.py and returns plain
dicts/lists — this keeps the three-state honesty rules (evaluated /
not evaluated / not collected) testable without a live tenant.
"""

KNOWN_RESULTS = frozenset({
    "reportOnlySuccess", "reportOnlyFailure",
    "reportOnlyNotApplied", "reportOnlyInterrupted",
    "success", "failure", "notApplied", "notEnabled",
})


def classify_result(raw_result: str) -> str:
    """Map a raw Graph appliedConditionalAccessPolicies result string to a
    known bucket, or 'unknownFutureValue' if Graph has added a new one we
    don't recognize yet. Never drop or silently merge an unrecognized value.
    """
    return raw_result if raw_result in KNOWN_RESULTS else "unknownFutureValue"


def extract_applied_policy_entry(signin: dict, policy_id: str) -> dict | None:
    """Find the appliedConditionalAccessPolicies[] entry matching policy_id,
    or None if the policy has no entry at all on this sign-in — meaning CA
    did not evaluate this policy for this specific request.
    """
    for entry in signin.get("appliedConditionalAccessPolicies", []):
        if entry.get("id") == policy_id:
            return entry
    return None


def _format_location(signin: dict) -> str:
    location = signin.get("location") or {}
    city = location.get("city") or "Unknown"
    country = location.get("countryOrRegion") or "Unknown"
    return f"{city}, {country}"


def aggregate_cell(sign_ins: list[dict], policy_id: str, max_samples: int = 50) -> dict:
    """Aggregate one user's sign-ins against one policy id.

    Returns counts per known/unknown result bucket, a separate
    not_evaluated_count for sign-ins that never got a Graph evaluation entry
    for this policy at all, and up to max_samples raw sample events tagged
    with their result_bucket ("not_evaluated" is a valid bucket value here,
    distinct from every real Graph result string).
    """
    counts: dict[str, int] = {}
    not_evaluated_count = 0
    sample_events: list[dict] = []

    for signin in sign_ins:
        entry = extract_applied_policy_entry(signin, policy_id)
        if entry is None:
            not_evaluated_count += 1
            bucket = "not_evaluated"
        else:
            bucket = classify_result(entry.get("result", ""))
            counts[bucket] = counts.get(bucket, 0) + 1

        if len(sample_events) < max_samples:
            sample_events.append({
                "timestamp": signin.get("createdDateTime"),
                "app": signin.get("appDisplayName"),
                "location": _format_location(signin),
                "device_compliant": (signin.get("deviceDetail") or {}).get("isCompliant"),
                "result_bucket": bucket,
            })

    return {
        "not_collected": False,
        "counts": counts,
        "not_evaluated_count": not_evaluated_count,
        "total_signins": len(sign_ins),
        "sample_events": sample_events,
    }
