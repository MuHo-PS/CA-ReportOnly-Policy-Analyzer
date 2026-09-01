import json
import os
import tempfile

from report_renderer import render_report, write_report
from aggregate import aggregate_user_policy_matrix

USERS = [{"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"}]
POLICIES = [{"id": "p1", "displayName": "Require MFA (report-only)", "state": "enabledForReportingButNotEnforced"}]
TEMPLATE_PATH = "templates/report.html"


def _matrix_result():
    signins_by_user = {"u1": [{
        "createdDateTime": "2026-08-01T10:00:00Z",
        "appDisplayName": "Office 365",
        "location": {"city": "Cairo", "countryOrRegion": "EG"},
        "deviceDetail": {"isCompliant": True},
        "appliedConditionalAccessPolicies": [{"id": "p1", "result": "reportOnlySuccess"}],
    }]}
    return aggregate_user_policy_matrix(USERS, POLICIES, signins_by_user, {})


def test_render_report_embeds_valid_json_with_matrix_data():
    matrix_result = _matrix_result()
    meta = {"total_signins": 1, "requested_days": 30, "actual_days_covered": 30}
    html = render_report(matrix_result, USERS, POLICIES, meta, TEMPLATE_PATH)

    assert "__REPORT_DATA__" not in html  # placeholder must be substituted
    start = html.index("const REPORT_DATA = ") + len("const REPORT_DATA = ")
    end = html.index(";\n", start)
    embedded = json.loads(html[start:end])

    assert embedded["users"] == USERS
    assert embedded["policies"] == POLICIES
    assert embedded["meta"] == meta
    assert embedded["matrix"]["u1"]["p1"]["counts"] == {"reportOnlySuccess": 1}
    assert "policy_totals" in embedded
    assert embedded["policy_totals"]["p1"]["counts"] == {"reportOnlySuccess": 1}


def test_render_report_escapes_script_closing_tag_in_display_names():
    tricky_users = [{"id": "u1", "displayName": "Alice</script><script>alert(1)</script>",
                      "userPrincipalName": "alice@contoso.com"}]
    matrix_result = aggregate_user_policy_matrix(tricky_users, POLICIES, {}, {})
    html = render_report(matrix_result, tricky_users, POLICIES,
                          {"total_signins": 0, "requested_days": 30, "actual_days_covered": 30},
                          TEMPLATE_PATH)
    assert "</script><script>alert(1)</script>" not in html
    assert "<\\/script>" in html


def test_template_escapes_dynamic_html_injection_sites():
    # A Graph-sourced displayName containing an HTML injection payload that
    # does NOT contain the literal substring "</script>" would sail past the
    # script-closing-tag escaping done in report_renderer.py, but would still
    # execute as real markup if the client-side JS assigns it into innerHTML
    # unescaped. The template must run every such value through an escaping
    # helper before it reaches innerHTML.
    payload = "<img src=x onerror=alert(1)>"
    tricky_users = [{"id": "u1", "displayName": payload, "userPrincipalName": "alice@contoso.com"}]
    matrix_result = aggregate_user_policy_matrix(tricky_users, POLICIES, {}, {})
    html = render_report(matrix_result, tricky_users, POLICIES,
                          {"total_signins": 0, "requested_days": 30},
                          TEMPLATE_PATH)
    # The raw payload must not appear literally in the rendered output at all
    # (it only ever appears JSON-encoded inside REPORT_DATA, never as bare
    # markup in the surrounding HTML/JS source).
    assert html.count(payload) <= 1  # at most the one JSON-encoded occurrence

    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template = f.read()

    assert "function escapeHtml(" in template

    # showDrillDown must escape every dynamic field it interpolates into HTML
    assert "escapeHtml(user.displayName)" in template
    assert "escapeHtml(policy.displayName)" in template
    assert "escapeHtml(cell.reason)" in template
    assert "escapeHtml(e.timestamp)" in template
    assert "escapeHtml(e.app)" in template
    assert "escapeHtml(e.location)" in template
    assert "escapeHtml(e.result_bucket)" in template

    # The per-policy chart heading must also escape the policy display name.
    assert "<h3>${escapeHtml(policy.displayName)}</h3>" in template


def test_write_report_writes_html_to_disk():
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = os.path.join(tmp_dir, "report.html")
        write_report("<html>test</html>", output_path)
        with open(output_path, "r", encoding="utf-8") as f:
            assert f.read() == "<html>test</html>"
