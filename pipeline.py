"""Pure scope-resolution logic — no network I/O. fetch_group_members is
injected as a callable so this module stays testable without graph_client.
"""


def resolve_user_scope(selection: dict, discovered_users: list[dict], fetch_group_members) -> list[dict]:
    """Turn a picker-page selection into a concrete, deduped list of full
    user records (each pulled from discovered_users, never invented).

    selection shape: {"all_users": bool, "user_ids": [str], "group_ids": [str]}
    fetch_group_members: callable(group_id: str) -> list[{"id": str, ...}]
    """
    if selection.get("all_users"):
        return list(discovered_users)

    users_by_id = {user["id"]: user for user in discovered_users}
    selected_ids: dict[str, None] = {}  # ordered set

    for user_id in selection.get("user_ids", []):
        if user_id in users_by_id:
            selected_ids[user_id] = None

    for group_id in selection.get("group_ids", []):
        for member in fetch_group_members(group_id):
            member_id = member["id"]
            if member_id in users_by_id:
                selected_ids[member_id] = None

    return [users_by_id[user_id] for user_id in selected_ids]
