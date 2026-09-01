from aggregate import classify_result, KNOWN_RESULTS, extract_applied_policy_entry, aggregate_cell, aggregate_user_policy_matrix, aggregate_policy_totals


def test_known_report_only_results_pass_through():
    for value in (
        "reportOnlySuccess",
        "reportOnlyFailure",
        "reportOnlyNotApplied",
        "reportOnlyInterrupted",
        "success",
        "failure",
        "notApplied",
        "notEnabled",
    ):
        assert classify_result(value) == value


def test_unrecognized_result_maps_to_unknown_future_value():
    assert classify_result("somethingGraphAddsLater") == "unknownFutureValue"


def test_known_results_constant_matches_expected_set():
    assert KNOWN_RESULTS == frozenset({
        "reportOnlySuccess", "reportOnlyFailure",
        "reportOnlyNotApplied", "reportOnlyInterrupted",
        "success", "failure", "notApplied", "notEnabled",
    })


def _signin(policies=None, created="2026-08-01T10:00:00Z", app="Office 365",
            city="Cairo", country="EG", compliant=None):
    return {
        "createdDateTime": created,
        "appDisplayName": app,
        "location": {"city": city, "countryOrRegion": country},
        "deviceDetail": {"isCompliant": compliant},
        "appliedConditionalAccessPolicies": policies or [],
    }


def test_extract_applied_policy_entry_finds_matching_id():
    signin = _signin(policies=[
        {"id": "policy-a", "result": "reportOnlySuccess"},
        {"id": "policy-b", "result": "notApplied"},
    ])
    entry = extract_applied_policy_entry(signin, "policy-b")
    assert entry == {"id": "policy-b", "result": "notApplied"}


def test_extract_applied_policy_entry_returns_none_when_absent():
    signin = _signin(policies=[{"id": "policy-a", "result": "success"}])
    assert extract_applied_policy_entry(signin, "policy-z") is None


def test_aggregate_cell_buckets_evaluated_results():
    sign_ins = [
        _signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}]),
        _signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}]),
        _signin(policies=[{"id": "p1", "result": "reportOnlyFailure"}]),
    ]
    cell = aggregate_cell(sign_ins, "p1")
    assert cell["not_collected"] is False
    assert cell["counts"] == {"reportOnlySuccess": 2, "reportOnlyFailure": 1}
    assert cell["not_evaluated_count"] == 0
    assert cell["total_signins"] == 3


def test_aggregate_cell_counts_not_evaluated_separately_from_results():
    sign_ins = [
        _signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}]),
        _signin(policies=[{"id": "other-policy", "result": "success"}]),  # no p1 entry
        _signin(policies=[]),  # CA evaluated nothing for this event
    ]
    cell = aggregate_cell(sign_ins, "p1")
    assert cell["counts"] == {"reportOnlySuccess": 1}
    assert cell["not_evaluated_count"] == 2
    assert cell["total_signins"] == 3


def test_aggregate_cell_unknown_result_gets_its_own_bucket():
    sign_ins = [_signin(policies=[{"id": "p1", "result": "somethingNew"}])]
    cell = aggregate_cell(sign_ins, "p1")
    assert cell["counts"] == {"unknownFutureValue": 1}


def test_aggregate_cell_handles_empty_signin_list():
    cell = aggregate_cell([], "p1")
    assert cell == {
        "not_collected": False,
        "counts": {},
        "not_evaluated_count": 0,
        "total_signins": 0,
        "sample_events": [],
    }


def test_aggregate_cell_caps_sample_events_at_max_samples():
    sign_ins = [_signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}])
                for _ in range(10)]
    cell = aggregate_cell(sign_ins, "p1", max_samples=3)
    assert len(cell["sample_events"]) == 3
    assert cell["total_signins"] == 10
    assert cell["counts"] == {"reportOnlySuccess": 10}  # counts unaffected by cap


def test_aggregate_cell_sample_event_shape():
    sign_ins = [_signin(policies=[{"id": "p1", "result": "reportOnlyFailure"}],
                         app="Exchange", city="Giza", country="EG", compliant=False)]
    cell = aggregate_cell(sign_ins, "p1")
    sample = cell["sample_events"][0]
    assert sample == {
        "timestamp": "2026-08-01T10:00:00Z",
        "app": "Exchange",
        "location": "Giza, EG",
        "device_compliant": False,
        "result_bucket": "reportOnlyFailure",
    }


def test_aggregate_cell_sample_event_result_bucket_is_not_evaluated_when_absent():
    sign_ins = [_signin(policies=[])]
    cell = aggregate_cell(sign_ins, "p1")
    assert cell["sample_events"][0]["result_bucket"] == "not_evaluated"


USERS = [
    {"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"},
    {"id": "u2", "displayName": "Bob", "userPrincipalName": "bob@contoso.com"},
]
POLICIES = [
    {"id": "p1", "displayName": "Require MFA (report-only)", "state": "enabledForReportingButNotEnforced"},
]


def test_matrix_has_one_cell_per_user_per_policy():
    signins_by_user = {
        "u1": [_signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}])],
        "u2": [_signin(policies=[{"id": "p1", "result": "reportOnlyNotApplied"}])],
    }
    result = aggregate_user_policy_matrix(USERS, POLICIES, signins_by_user, {})
    matrix = result["matrix"]
    assert set(matrix.keys()) == {"u1", "u2"}
    assert matrix["u1"]["p1"]["counts"] == {"reportOnlySuccess": 1}
    assert matrix["u2"]["p1"]["counts"] == {"reportOnlyNotApplied": 1}


def test_matrix_marks_not_collected_users_without_calling_aggregate_cell():
    signins_by_user = {"u1": [_signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}])]}
    collection_errors = {"u2": "403 insufficient privileges reading AuditLog for bob@contoso.com"}
    result = aggregate_user_policy_matrix(USERS, POLICIES, signins_by_user, collection_errors)
    assert result["matrix"]["u2"]["p1"] == {
        "not_collected": True,
        "reason": "403 insufficient privileges reading AuditLog for bob@contoso.com",
    }
    assert result["matrix"]["u1"]["p1"]["not_collected"] is False


def test_policy_totals_sum_across_users_and_track_not_collected_separately():
    signins_by_user = {
        "u1": [_signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}]),
               _signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}])],
        "u2": [_signin(policies=[])],  # not evaluated
    }
    collection_errors = {}
    result = aggregate_user_policy_matrix(
        USERS + [{"id": "u3", "displayName": "Carol", "userPrincipalName": "carol@contoso.com"}],
        POLICIES,
        signins_by_user,
        {"u3": "token expired mid-pull"},
    )
    totals = aggregate_policy_totals(result["matrix"], "p1")
    assert totals["counts"] == {"reportOnlySuccess": 2}
    assert totals["not_evaluated_count"] == 1
    assert totals["not_collected_users"] == 1
    assert totals["total_signins"] == 3
