import pytest
from BlockDomain import (
    ACTION_CREATED,
    ACTION_MODIFIED,
    ACTION_UNCHANGED,
    OBJECT_NAME_PREFIX,
    MAX_OBJECT_NAME_LENGTH,
    RESULT_FAILED,
    RESULT_SUCCESS,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_SKIPPED,
    PanOs,
    derive_object_name,
    is_valid_fqdn,
    is_wildcard,
    most_significant_action,
    validate_domains,
)


def ok_entry(entry_context=None, contents="ok"):
    """Build a minimal successful execute_command entry."""
    return {"Type": 1, "Contents": contents, "HumanReadable": "", "EntryContext": entry_context or {}}


def err_entry(contents="error"):
    """Build a minimal error execute_command entry (Type 4 == entryTypes['error'])."""
    return {"Type": 4, "Contents": contents, "HumanReadable": "", "EntryContext": {}}


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("*.evil.com", True),
        ("evil.*.com", True),
        ("evil.example.com", False),
        ("sub.domain.co.uk", False),
    ],
)
def test_is_wildcard(domain, expected):
    assert is_wildcard(domain) is expected


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("evil.example.com", True),
        ("sub.domain.co.uk", True),
        ("a.b", True),
        ("no-dot", False),
        ("*.evil.com", False),
        ("-leading.example.com", False),
        ("trailing-.example.com", False),
        ("space in.example.com", False),
        ("", False),
    ],
)
def test_is_valid_fqdn(domain, expected):
    assert is_valid_fqdn(domain) is expected


def test_derive_object_name_simple():
    assert derive_object_name("evil.example.com") == "Cortex-evil.example.com"


def test_derive_object_name_is_deterministic():
    assert derive_object_name("evil.example.com") == derive_object_name("evil.example.com")


def test_derive_object_name_sanitises_illegal_chars():
    # Underscores are not valid PAN-OS object-name characters; they get normalised to hyphens.
    assert derive_object_name("bad_domain.example.com") == "Cortex-bad-domain.example.com"


def test_derive_object_name_overflow_truncates_and_hashes():
    long_domain = ("a" * 80) + ".example.com"
    name = derive_object_name(long_domain)
    assert len(name) <= MAX_OBJECT_NAME_LENGTH
    assert name.startswith(OBJECT_NAME_PREFIX)
    # Overflow names are still deterministic.
    assert name == derive_object_name(long_domain)


def test_validate_domains_splits_valid_and_skipped():
    valid, skipped = validate_domains(["evil.example.com", "*.evil.com", "no-dot", "phish.attacker.net"])

    assert valid == ["evil.example.com", "phish.attacker.net"]
    assert len(skipped) == 2

    wildcard_row = next(row for row in skipped if row["Domain"] == "*.evil.com")
    assert wildcard_row["Status"] == STATUS_SKIPPED
    assert wildcard_row["Result"] == RESULT_SUCCESS
    assert wildcard_row["Action"] == ACTION_UNCHANGED
    assert "Wildcard" in wildcard_row["Message"]

    invalid_row = next(row for row in skipped if row["Domain"] == "no-dot")
    assert invalid_row["Status"] == STATUS_SKIPPED
    assert "Invalid FQDN" in invalid_row["Message"]


def test_validate_domains_all_valid():
    valid, skipped = validate_domains(["a.com", "b.org"])
    assert valid == ["a.com", "b.org"]
    assert skipped == []


@pytest.mark.parametrize(
    "actions, expected",
    [
        ([], ACTION_UNCHANGED),
        ([ACTION_UNCHANGED, ACTION_UNCHANGED], ACTION_UNCHANGED),
        ([ACTION_UNCHANGED, ACTION_MODIFIED], ACTION_MODIFIED),
        ([ACTION_MODIFIED, ACTION_CREATED], ACTION_CREATED),
        ([ACTION_CREATED, ACTION_UNCHANGED], ACTION_CREATED),
    ],
)
def test_most_significant_action(actions, expected):
    assert most_significant_action(actions) == expected


def _pan_os(domains):
    return PanOs(
        {
            "domains": domains,
            "rule_name": "Cortex - Block Domain",
            "address_group": "Blocked Domains - Cortex",
            "tag": "cortex-blocked-domains",
            "log_forwarding_name": "",
            "auto_commit": True,
        }
    )


def _mock_execute(monkeypatch, side_effect):
    """Patch BlockDomain.demisto.executeCommand to yield the given responses in order."""
    import BlockDomain

    responses = iter(side_effect)
    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", lambda *a, **k: next(responses))


def test_process_domains_create_everything(monkeypatch):
    # Group missing -> create group; address missing -> create address; rule missing -> create + move.
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": []})],  # list-address-groups (missing)
            [err_entry("not found")],  # get-address (missing)
            [ok_entry({"Panorama.Addresses": [{"Name": "Cortex-evil.example.com"}]})],  # create-address
            [ok_entry()],  # create-address-group
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static"}]})],  # re-list group
            [ok_entry({"Panorama.SecurityRule": []})],  # list-rules (missing)
            [ok_entry()],  # create-rule
            [ok_entry()],  # move-rule
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert len(rows) == 1
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Result"] == RESULT_SUCCESS
    assert rows[0]["Action"] == ACTION_CREATED
    assert rows[0]["RuleName"] == "Cortex - Block Domain"


def test_process_domains_all_unchanged(monkeypatch):
    obj = "Cortex-evil.example.com"
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj]}]})],
            [ok_entry({"Panorama.Addresses": [{"Name": obj}]})],  # get-address (exists)
            [ok_entry({"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain"}]})],  # list-rules (exists)
            [ok_entry()],  # move-rule
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Action"] == ACTION_UNCHANGED


def test_process_domains_modified_when_added_to_existing_group(monkeypatch):
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": []}]})],
            [err_entry("not found")],  # get-address (missing)
            [ok_entry()],  # create-address
            [ok_entry()],  # edit-address-group (add member)
            [ok_entry({"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain"}]})],  # list-rules (exists)
            [ok_entry()],  # move-rule
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Action"] == ACTION_CREATED  # object was created -> most significant


def test_process_domains_dynamic_group_is_skipped(monkeypatch):
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "dynamic", "Match": "x"}]})],
            [err_entry("not found")],  # get-address (missing)
            [ok_entry()],  # create-address
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_SKIPPED
    assert rows[0]["Result"] == RESULT_SUCCESS
    assert "dynamic" in rows[0]["Message"]


def test_process_domains_failure_marks_row_failed(monkeypatch):
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": []})],  # list-address-groups
            [err_entry("not found")],  # get-address (missing)
            [err_entry("permission denied")],  # create-address fails
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_FAILED
    assert rows[0]["Result"] == RESULT_FAILED
    assert "permission denied" in rows[0]["Message"]
