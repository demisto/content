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
    build_final_command_results,
    build_verbose_human_readable,
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


def test_validate_domains_splits_valid_and_failed():
    valid, failed = validate_domains(["evil.example.com", "*.evil.com", "no-dot", "phish.attacker.net"])

    assert valid == ["evil.example.com", "phish.attacker.net"]
    assert len(failed) == 2

    wildcard_row = next(row for row in failed if row["Domain"] == "*.evil.com")
    assert wildcard_row["Status"] == STATUS_FAILED
    assert wildcard_row["Result"] == RESULT_FAILED
    assert wildcard_row["Action"] == ACTION_UNCHANGED
    assert "Wildcard" in wildcard_row["Message"]

    invalid_row = next(row for row in failed if row["Domain"] == "no-dot")
    assert invalid_row["Status"] == STATUS_FAILED
    assert invalid_row["Result"] == RESULT_FAILED
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
            "domain_list": domains,
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
    # Group missing + rule missing: address is created first, then group is seeded with that
    # object, then rule is created (destination must resolve to an existing group), then move.
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": []})],  # list-address-groups (missing)
            [ok_entry({"Panorama.SecurityRule": []})],  # list-rules (missing)
            [err_entry("not found")],  # get-address (missing)
            [ok_entry()],  # create-address
            [ok_entry()],  # create-address-group (seeded with first member)
            [ok_entry()],  # create-rule (destination = the now-existing group)
            [ok_entry()],  # move-rule
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert len(rows) == 1
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Result"] == RESULT_SUCCESS
    assert rows[0]["Action"] == ACTION_CREATED
    assert rows[0]["RuleName"] == "Cortex - Block Domain"


def test_process_domains_missing_group_created_lazily_with_first_object(monkeypatch):
    # Regression for two PAN-OS ordering rules:
    #   1. pan-os-create-address-group refuses a static group without members -> must be created
    #      AFTER pan-os-create-address, and seeded with the first object.
    #   2. pan-os-create-rule validates that `destination` references an existing object -> must
    #      be created AFTER pan-os-create-address-group.
    calls: list = []

    def _capture(name, args):
        calls.append((name, args))
        seq = {
            "pan-os-list-address-groups": [ok_entry({"Panorama.AddressGroups": []})],
            "pan-os-list-rules": [ok_entry({"Panorama.SecurityRule": []})],
            "pan-os-create-rule": [ok_entry()],
            "pan-os-move-rule": [ok_entry()],
            "pan-os-get-address": [err_entry("not found")],
            "pan-os-create-address": [ok_entry()],
            "pan-os-create-address-group": [ok_entry()],
        }
        return seq.get(name, [ok_entry()])

    import BlockDomain

    monkeypatch.setattr(BlockDomain.demisto, "executeCommand", _capture)

    _pan_os(["evil.example.com"]).process_domains()

    names = [c[0] for c in calls]
    # Ordering constraint 1: address must be created before the group.
    assert names.index("pan-os-create-address") < names.index("pan-os-create-address-group")
    # Ordering constraint 2: group must exist before the rule is created (destination resolves).
    assert names.index("pan-os-create-address-group") < names.index("pan-os-create-rule")
    # Group create carries the seed member (never an empty static group).
    group_create_args = next(args for name, args in calls if name == "pan-os-create-address-group")
    assert group_create_args["type"] == "static"
    assert group_create_args["addresses"] == "Cortex-evil.example.com"
    # Rule create destination points at the group.
    rule_create_args = next(args for name, args in calls if name == "pan-os-create-rule")
    assert rule_create_args["destination"] == "Blocked Domains - Cortex"
    # No pan-os-edit-address-group was called for the first (seed) domain.
    assert "pan-os-edit-address-group" not in names


def test_process_domains_all_unchanged(monkeypatch):
    obj = "Cortex-evil.example.com"
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj]}]})],
            [
                ok_entry(
                    {"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain", "Destination": ["Blocked Domains - Cortex"]}]}
                )
            ],
            [ok_entry()],  # move-rule
            [ok_entry({"Panorama.Addresses": [{"Name": obj}]})],  # get-address (exists)
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
            [
                ok_entry(
                    {"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain", "Destination": ["Blocked Domains - Cortex"]}]}
                )
            ],
            [ok_entry()],  # move-rule
            [err_entry("not found")],  # get-address (missing)
            [ok_entry()],  # create-address
            [ok_entry()],  # edit-address-group (add member)
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Action"] == ACTION_CREATED  # object was created -> most significant


def test_process_domains_existing_rule_missing_group_is_edited(monkeypatch):
    obj = "Cortex-evil.example.com"
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "static", "Addresses": [obj]}]})],
            # Rule exists but its destination does not reference our group -> triggers edit-rule.
            [ok_entry({"Panorama.SecurityRule": [{"Name": "Cortex - Block Domain", "Destination": ["something-else"]}]})],
            [ok_entry()],  # edit-rule (add destination)
            [ok_entry()],  # move-rule
            [ok_entry({"Panorama.Addresses": [{"Name": obj}]})],  # get-address (exists)
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_DONE
    assert rows[0]["Action"] == ACTION_UNCHANGED  # object + membership unchanged; rule edit is a group-level fix


def test_process_domains_dynamic_group_is_skipped(monkeypatch):
    _mock_execute(
        monkeypatch,
        [
            [ok_entry({"Panorama.AddressGroups": [{"Name": "Blocked Domains - Cortex", "Type": "dynamic", "Match": "x"}]})],
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
            [ok_entry({"Panorama.AddressGroups": []})],  # list-address-groups (missing, deferred)
            [ok_entry({"Panorama.SecurityRule": []})],  # list-rules (missing, deferred)
            [err_entry("not found")],  # get-address (missing)
            [err_entry("permission denied")],  # create-address fails before group/rule are touched
        ],
    )
    rows = _pan_os(["evil.example.com"]).process_domains()
    assert rows[0]["Status"] == STATUS_FAILED
    assert rows[0]["Result"] == RESULT_FAILED
    assert "permission denied" in rows[0]["Message"]


def test_build_verbose_human_readable_joins_with_blank_lines():
    responses = [
        [ok_entry(contents="c1")],  # no HumanReadable -> skipped
        [{"Type": 1, "Contents": "c2", "HumanReadable": "HR-two", "EntryContext": {}}],
        [{"Type": 1, "Contents": "c3", "HumanReadable": "HR-three", "EntryContext": {}}],
    ]
    verbose_hr = build_verbose_human_readable(responses)
    # Leading blank line then each HR separated by a blank line.
    assert verbose_hr == "\n\nHR-two\n\nHR-three"


def test_build_verbose_human_readable_empty_when_no_hr():
    assert build_verbose_human_readable([[ok_entry(contents="c1")]]) == ""
    assert build_verbose_human_readable([]) == ""


def test_build_final_command_results_non_verbose_is_table_only():
    rows = [
        {
            "Domain": "a.com",
            "Brand": "Panorama",
            "Instance": "",
            "Status": STATUS_DONE,
            "Result": RESULT_SUCCESS,
            "Action": ACTION_CREATED,
            "RuleName": "Cortex - Block Domain",
            "Message": "ok",
        }
    ]
    responses = [[{"Type": 1, "Contents": "c", "HumanReadable": "HR", "EntryContext": {}}]]

    result = build_final_command_results(rows, verbose=False, responses=responses)
    assert result.outputs_prefix == "BlockDomainResults"
    assert result.outputs == rows
    assert "a.com" in result.readable_output
    assert "HR" not in result.readable_output  # verbose not appended


def test_build_final_command_results_verbose_appends_command_hr():
    rows = [
        {
            "Domain": "a.com",
            "Brand": "Panorama",
            "Instance": "",
            "Status": STATUS_DONE,
            "Result": RESULT_SUCCESS,
            "Action": ACTION_CREATED,
            "RuleName": "Cortex - Block Domain",
            "Message": "ok",
        }
    ]
    responses = [[{"Type": 1, "Contents": "c", "HumanReadable": "HR-one", "EntryContext": {}}]]

    result = build_final_command_results(rows, verbose=True, responses=responses)
    assert result.outputs == rows
    assert "a.com" in result.readable_output  # summary table present
    assert result.readable_output.endswith("HR-one")  # verbose appended after the table
