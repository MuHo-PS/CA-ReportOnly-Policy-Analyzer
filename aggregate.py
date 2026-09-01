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
