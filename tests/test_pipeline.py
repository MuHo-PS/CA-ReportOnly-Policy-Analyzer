from pipeline import resolve_user_scope

DISCOVERED_USERS = [
    {"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"},
    {"id": "u2", "displayName": "Bob", "userPrincipalName": "bob@contoso.com"},
    {"id": "u3", "displayName": "Carol", "userPrincipalName": "carol@contoso.com"},
]


def test_all_users_scope_returns_full_discovered_list():
    selection = {"all_users": True, "user_ids": [], "group_ids": []}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fetch_group_members=lambda gid: [])
    assert result == DISCOVERED_USERS


def test_specific_users_scope_returns_only_selected():
    selection = {"all_users": False, "user_ids": ["u2"], "group_ids": []}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fetch_group_members=lambda gid: [])
    assert result == [DISCOVERED_USERS[1]]


def test_groups_scope_expands_via_fetch_group_members():
    def fake_fetch_group_members(group_id):
        assert group_id == "g1"
        return [{"id": "u1"}, {"id": "u3"}]

    selection = {"all_users": False, "user_ids": [], "group_ids": ["g1"]}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fake_fetch_group_members)
    assert {u["id"] for u in result} == {"u1", "u3"}


def test_mixed_users_and_groups_are_unioned_and_deduped():
    def fake_fetch_group_members(group_id):
        return [{"id": "u2"}]  # overlaps with the individually selected user below

    selection = {"all_users": False, "user_ids": ["u2"], "group_ids": ["g1"]}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fake_fetch_group_members)
    assert [u["id"] for u in result] == ["u2"]  # deduped, not doubled


def test_group_member_not_in_discovered_users_is_skipped():
    def fake_fetch_group_members(group_id):
        return [{"id": "u-not-discovered"}]

    selection = {"all_users": False, "user_ids": [], "group_ids": ["g1"]}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fake_fetch_group_members)
    assert result == []
