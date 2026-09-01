from aggregate import classify_result, KNOWN_RESULTS


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
