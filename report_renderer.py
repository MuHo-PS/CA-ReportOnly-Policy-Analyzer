"""Renders the final self-contained static HTML report."""
import json

from aggregate import aggregate_policy_totals


def render_report(matrix_result: dict, users: list[dict], policies: list[dict],
                   meta: dict, template_path: str) -> str:
    matrix = matrix_result["matrix"]
    policy_totals = {
        policy["id"]: aggregate_policy_totals(matrix, policy["id"])
        for policy in policies
    }

    embedded = {
        "users": users,
        "policies": policies,
        "matrix": matrix,
        "policy_totals": policy_totals,
        "meta": meta,
    }
    # Escape a literal "</script>" inside embedded data so it can never
    # prematurely close the report's own <script> block.
    embedded_json = json.dumps(embedded).replace("</script>", "<\\/script>")

    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    return template.replace("__REPORT_DATA__", embedded_json)


def write_report(html: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
